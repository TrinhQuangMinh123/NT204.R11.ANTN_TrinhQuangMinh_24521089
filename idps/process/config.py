"""Config — tham số runtime đọc từ tệp ngoài mã nguồn (REQ-36, ADR-24, C-19).

Ba module của bài 2 (Decoder, Preprocessor, FlowTracker) đọc ngưỡng và giới hạn
từ đây, không hard-code. Mọi tham số nằm ở Phụ lục J; thứ tự ưu tiên:
mặc định trong mã < tệp cấu hình < `--set`.

Hai nguyên tắc có chủ đích:
  1. **Khoá lạ -> lỗi, không bỏ qua.** Một tham số viết sai chính tả mà chương
     trình im lặng dùng mặc định là cách chắc chắn nhất để một test case "chạy
     đúng" vì lý do sai. Ngoại lệ DUY NHẤT: khoá bắt đầu bằng `_` được bỏ qua
     (để viết chú thích trong tệp — ADR-24).
  2. **Lỗi lộ ra trước packet đầu tiên** (REQ-36.3): main.py dựng Config trước
     khi mở nguồn, nên một tệp cấu hình hỏng làm exit ngay, không mất capture.

Chỉ import `json` của thư viện chuẩn: JSON có ở mọi bản Python (`tomllib` chỉ
từ 3.11, máy phát triển chạy 3.10), và dự án đã đọc/ghi JSON ở mọi chỗ khác.
Không import capture/decode nên tầng process/ vẫn độc lập (I-20).
"""
import json


class ConfigError(Exception):
    """Cấu hình không dùng được — main.py in ra rồi exit 1 (REQ-36.3).

    Là ngoại lệ vì một cấu hình sai làm cả lần chạy mất nghĩa (giống SourceError
    của bài 1): không có gì để tiếp tục. Khác với `--set` sai cú pháp — đó là lỗi
    tham số dòng lệnh, argparse lo và exit 2 (design §5.4).
    """


# --- Đặc tả tham số (Phụ lục J) --------------------------------------------
# Dạng dữ liệu để thêm tham số = thêm một dòng, không sửa hàm kiểm tra (NFR-15).

# Ngưỡng im lặng theo giây: (mặc định, cho phép bằng 0). `tcp.closed` cho >= 0
# vì "giữ 0 giây" nghĩa là đóng flow CLOSED ngay packet sau — một lựa chọn hợp lệ.
_TIMEOUTS = {
    "tcp.new": (60, False),
    "tcp.established": (3600, False),
    "tcp.closed": (120, True),
    "udp.new": (30, False),
    "udp.established": (300, False),
}

# Giới hạn dạng số nguyên dương (số flow, số byte).
_COUNTS = {
    "max_active_flows": 10000,
    "max_decode_bytes": 65536,
    "max_reassembly_bytes": 1048576,
    "max_reassembly_total_bytes": 16777216,
}

_POLICY_VALUES = ("mark", "skip")

# Top-level keys là object lồng; khoá con của chúng thành khoá dạng chấm.
_NESTED_GROUPS = ("tcp", "udp")


def _build_params():
    """Gộp ba nhóm trên thành một bảng tra duy nhất: khoá chấm -> đặc tả."""
    params = {}
    for key, (default, allow_zero) in _TIMEOUTS.items():
        params[key] = {
            "default": default,
            "kind": "number",
            "allow_zero": allow_zero,
            "expected": "number >= 0" if allow_zero else "number > 0",
        }
    for key, default in _COUNTS.items():
        params[key] = {
            "default": default,
            "kind": "int",
            "allow_zero": False,
            "expected": "integer > 0",
        }
    params["missing_data_policy"] = {
        "default": "mark",
        "kind": "enum",
        "values": _POLICY_VALUES,
        "expected": "one of: " + ", ".join(_POLICY_VALUES),
    }
    return params


_PARAMS = _build_params()


def _validate(key, raw):
    """Ép kiểu + kiểm khoảng một giá trị cho tham số `key`.

    `raw` có thể đã đúng kiểu (đọc từ JSON) hoặc là chuỗi (từ `--set tcp.new=5`),
    nên hàm xử lý cả hai. Sai kiểu hoặc ngoài khoảng -> ConfigError nêu TÊN tham
    số và GIÁ TRỊ NHẬN ĐƯỢC (REQ-26.5 lối thông báo, design §5.4).
    """
    spec = _PARAMS[key]
    kind = spec["kind"]
    try:
        if kind == "enum":
            if not isinstance(raw, str) or raw not in spec["values"]:
                raise ValueError
            return raw
        # bool là lớp con của int trong Python -> phải loại trước, nếu không
        # JSON `true` lọt qua thành 1 cho một tham số số.
        if isinstance(raw, bool):
            raise ValueError
        if kind == "int":
            value = int(raw) if isinstance(raw, str) else raw
            if not isinstance(value, int):
                raise ValueError          # float cho tham số số nguyên -> lỗi
        else:  # number: chấp nhận int hoặc float
            if isinstance(raw, str):
                try:
                    value = int(raw)
                except ValueError:
                    value = float(raw)
            elif isinstance(raw, (int, float)):
                value = raw
            else:
                raise ValueError
        if spec["allow_zero"]:
            if value < 0:
                raise ValueError
        elif value <= 0:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise ConfigError(
            f"invalid value for {key}: {raw!r} (expected {spec['expected']})"
        )


def _flatten_file(data):
    """Object JSON lồng -> dict khoá chấm; bỏ `_*`, bắt khoá lạ.

    Trả về giá trị RAW (chưa ép kiểu) để Config.load kiểm từng giá trị bằng đúng
    một đường (_validate) cho cả tệp và `--set`.
    """
    flat = {}
    for key, value in data.items():
        if key.startswith("_"):
            continue
        if key in _NESTED_GROUPS:
            if not isinstance(value, dict):
                raise ConfigError(
                    f"invalid value for {key}: {value!r} (expected object)"
                )
            for sub, subval in value.items():
                if sub.startswith("_"):
                    continue
                dotted = f"{key}.{sub}"
                if dotted not in _PARAMS:
                    raise ConfigError(f"unknown config parameter: {dotted}")
                flat[dotted] = subval
        elif key in _PARAMS:
            flat[key] = value
        else:
            raise ConfigError(f"unknown config parameter: {key}")
    return flat


class Config:
    """Tập tham số đã kiểm, bất biến sau khi dựng. Stage đọc bằng cfg["tcp.new"]."""

    def __init__(self, values):
        self.values = dict(values)

    def __getitem__(self, key):
        return self.values[key]

    def get(self, key, default=None):
        return self.values.get(key, default)

    @classmethod
    def load(cls, path=None, overrides=()):
        """Dựng Config: mặc định < tệp (nếu có) < overrides. Lỗi -> ConfigError.

        `path` = None nghĩa là không dùng tệp (main.py quyết định: tệp mặc định
        `idps-config.json` chỉ dùng khi tồn tại, còn `--config X` thiếu tệp thì
        lỗi — design §5.5). `overrides` là chuỗi (khoá_chấm, giá_trị_chuỗi) đã
        tách sẵn từ `--set` ở main.py (việc tách KEY=VALUE thuộc argparse -> exit 2).
        """
        values = {key: spec["default"] for key, spec in _PARAMS.items()}
        if path is not None:
            for key, raw in _flatten_file(cls._read_file(path)).items():
                values[key] = _validate(key, raw)
        for key, raw in overrides:
            if key not in _PARAMS:
                raise ConfigError(f"unknown config parameter: {key}")
            values[key] = _validate(key, raw)
        return cls(values)

    @staticmethod
    def _read_file(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            # strerror cho lý do hệ thống gọn ("No such file or directory"),
            # không lặp lại đường dẫn như str(exc) của một số OSError.
            reason = exc.strerror or exc
            raise ConfigError(f"cannot read config {path}: {reason}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # exc đã kèm số dòng/cột -> người sửa tệp biết chỗ nào sai.
            raise ConfigError(f"invalid config {path}: {exc}")
        if not isinstance(data, dict):
            raise ConfigError(
                f"invalid config {path}: top-level value must be an object"
            )
        return data

    def line(self):
        """Một dòng `config={…}` cho stdout — bằng chứng tự giải thích (REQ-36.4).

        `sort_keys=True` + khoá dạng chấm: `grep config=` ra đúng một dòng so
        sánh được giữa hai lần chạy (run.log của T12 phải nói được vì sao flow
        hết hạn). separators gọn cho khớp lối JSON của cả dự án.
        """
        body = json.dumps(self.values, sort_keys=True, separators=(",", ":"))
        return f"config={body}"
