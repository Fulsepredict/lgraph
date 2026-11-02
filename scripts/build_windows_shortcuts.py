"""
Генератор многослойной иконки Windows (`logo.ico`), ярлыка на Рабочем столе (`Lgraph.lnk`)
и консольной команды `lgraph` (`%LOCALAPPDATA%\\Microsoft\\WindowsApps\\lgraph.cmd`).

Почему реализовано на чистом Python 3.12 (`zlib` + `struct`) без сторонних пакетов (`Pillow`):
1. Любой пользователь после `git clone` получает нативную иконку `.ico` (16..256px с премультиплицированной
   прозрачностью RGBA) без установки компиляторов и графических библиотек.
2. Все пути передаются в PowerShell исключительно через переменные окружения (`$env:LGRAPH_SC_*`),
   что исключает поломку или инъекцию команд на путях с апострофами (`Alex's PC`) и кириллицей.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOGO_PNG_PATH = PROJECT_ROOT / "frontend" / "public" / "logo.png"
LOGO_ICO_PATH = PROJECT_ROOT / "frontend" / "public" / "logo.ico"
ICO_SIZES: tuple[int, ...] = (16, 32, 48, 64, 256)


def _paeth_predictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def decode_rgba_png(png_bytes: bytes) -> tuple[int, int, bytearray]:
    """Декодирует 8-битный RGBA PNG (включая все стандартные фильтры строк 0..4) в плоский буфер RGBA."""
    if png_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Файл logo.png не является корректным PNG.")

    pos = 8
    width = height = 0
    idat_chunks: list[bytes] = []

    while pos < len(png_bytes):
        length = struct.unpack(">I", png_bytes[pos : pos + 4])[0]
        chunk_type = png_bytes[pos + 4 : pos + 8]
        chunk_data = png_bytes[pos + 8 : pos + 8 + length]
        pos += 12 + length

        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", chunk_data)
            if bit_depth != 8 or color_type != 6 or interlace != 0:
                raise ValueError(f"Ожидался 8-bit non-interlaced RGBA PNG, получено depth={bit_depth}, type={color_type}.")
        elif chunk_type == b"IDAT":
            idat_chunks.append(chunk_data)
        elif chunk_type == b"IEND":
            break

    raw = zlib.decompress(b"".join(idat_chunks))
    stride = width * 4
    out = bytearray(width * height * 4)
    src_offset = 0

    for y in range(height):
        filt = raw[src_offset]
        src_offset += 1
        row_out_start = y * stride
        prev_row_start = (y - 1) * stride

        for x_byte in range(stride):
            val = raw[src_offset + x_byte]
            left = out[row_out_start + x_byte - 4] if x_byte >= 4 else 0
            up = out[prev_row_start + x_byte] if y > 0 else 0
            up_left = out[prev_row_start + x_byte - 4] if (y > 0 and x_byte >= 4) else 0

            if filt == 1:
                val = (val + left) & 0xFF
            elif filt == 2:
                val = (val + up) & 0xFF
            elif filt == 3:
                val = (val + ((left + up) >> 1)) & 0xFF
            elif filt == 4:
                val = (val + _paeth_predictor(left, up, up_left)) & 0xFF

            out[row_out_start + x_byte] = val
        src_offset += stride

    return width, height, out


def downsample_rgba_box(src_w: int, src_h: int, src_buf: bytearray, dst_size: int) -> bytes:
    """Уменьшает квадратное изображение с учётом премультиплицированной альфы (без тёмного ореола по краям)."""
    dst = bytearray(dst_size * dst_size * 4)
    scale_x = src_w / dst_size
    scale_y = src_h / dst_size

    for dy in range(dst_size):
        y0 = int(dy * scale_y)
        y1 = max(y0 + 1, int((dy + 1) * scale_y))
        for dx in range(dst_size):
            x0 = int(dx * scale_x)
            x1 = max(x0 + 1, int((dx + 1) * scale_x))

            sum_pr = sum_pg = sum_pb = sum_a = count = 0
            for sy in range(y0, min(y1, src_h)):
                row_idx = sy * src_w * 4
                for sx in range(x0, min(x1, src_w)):
                    idx = row_idx + sx * 4
                    r, g, b, a = src_buf[idx], src_buf[idx + 1], src_buf[idx + 2], src_buf[idx + 3]
                    sum_pr += r * a
                    sum_pg += g * a
                    sum_pb += b * a
                    sum_a += a
                    count += 1

            out_idx = (dy * dst_size + dx) * 4
            if sum_a > 0 and count > 0:
                dst[out_idx] = min(255, int(round(sum_pr / sum_a)))
                dst[out_idx + 1] = min(255, int(round(sum_pg / sum_a)))
                dst[out_idx + 2] = min(255, int(round(sum_pb / sum_a)))
                dst[out_idx + 3] = min(255, int(round(sum_a / count)))
    return bytes(dst)


def encode_rgba_png(width: int, height: int, rgba: bytes) -> bytes:
    """Упаковывает RGBA-буфер в компактный PNG-кадр для контейнера Windows `.ico`."""
    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    stride = width * 4
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        scanlines.extend(rgba[y * stride : (y + 1) * stride])

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    compressed = zlib.compress(bytes(scanlines), level=9)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", compressed) + _chunk(b"IEND", b"")


def build_multi_size_ico(png_path: Path, ico_path: Path) -> None:
    """Создаёт многослойный `.ico` (16, 32, 48, 64, 256 px) для чёткого рендера на любых DPI Windows."""
    src_w, src_h, src_rgba = decode_rgba_png(png_path.read_bytes())
    frames: list[tuple[int, bytes]] = []
    for sz in ICO_SIZES:
        resized = downsample_rgba_box(src_w, src_h, src_rgba, sz)
        frames.append((sz, encode_rgba_png(sz, sz, resized)))

    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    entries = bytearray()
    payload = bytearray()

    for sz, png_frame in frames:
        dim_byte = 0 if sz >= 256 else sz
        entries.extend(struct.pack("<BBBBHHII", dim_byte, dim_byte, 0, 0, 1, 32, len(png_frame), offset))
        payload.extend(png_frame)
        offset += len(png_frame)

    ico_path.write_bytes(header + bytes(entries) + bytes(payload))


def format_cmd_launcher_script(start_bat: Path) -> str:
    """Формирует `lgraph.cmd`, корректно работающий с UTF-8 / кириллическими путями в `cmd.exe`."""
    return (
        "@echo off\r\n"
        "setlocal\r\n"
        'set "_LG_CP="\r\n'
        "for /f \"tokens=2 delims=:.\" %%A in ('chcp') do set \"_LG_CP=%%A\"\r\n"
        "chcp 65001 >nul\r\n"
        f'call "{start_bat}" %*\r\n'
        'set "_LG_RC=%ERRORLEVEL%"\r\n'
        "if defined _LG_CP chcp %_LG_CP% >nul\r\n"
        "exit /b %_LG_RC%\r\n"
    )


def create_desktop_shortcut_and_cli() -> tuple[Path | None, Path | None]:
    """Создаёт ярлык `Lgraph.lnk` на Рабочем столе Windows и команду `lgraph.cmd` в WindowsApps."""
    if os.name != "nt":
        return None, None

    electron_exe = PROJECT_ROOT / "frontend" / "node_modules" / "electron" / "dist" / "electron.exe"
    frontend_dir = PROJECT_ROOT / "frontend"
    start_bat = PROJECT_ROOT / "START_APP.bat"

    cli_path: Path | None = None
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        win_apps = Path(local_app_data) / "Microsoft" / "WindowsApps"
        if win_apps.is_dir():
            cli_path = win_apps / "lgraph.cmd"
            cli_path.write_text(format_cmd_launcher_script(start_bat), encoding="utf-8")

    # Все пути передаются через env без интерполяции в исходный код PowerShell (защита от кавычек и спецсимволов)
    ps_env = dict(os.environ)
    ps_env["LGRAPH_SC_TARGET"] = str(electron_exe if electron_exe.is_file() else start_bat)
    ps_env["LGRAPH_SC_ARGS"] = f'"{frontend_dir}"' if electron_exe.is_file() else ""
    ps_env["LGRAPH_SC_WORKDIR"] = str(frontend_dir)
    ps_env["LGRAPH_SC_ICON"] = f"{LOGO_ICO_PATH},0"

    ps_script = (
        "$desk = [Environment]::GetFolderPath('Desktop'); "
        "$lnkPath = Join-Path $desk 'Lgraph.lnk'; "
        "$ws = New-Object -ComObject WScript.Shell; "
        "$sc = $ws.CreateShortcut($lnkPath); "
        "$sc.TargetPath = $env:LGRAPH_SC_TARGET; "
        "if ($env:LGRAPH_SC_ARGS) { $sc.Arguments = $env:LGRAPH_SC_ARGS }; "
        "$sc.WorkingDirectory = $env:LGRAPH_SC_WORKDIR; "
        "$sc.IconLocation = $env:LGRAPH_SC_ICON; "
        "$sc.Description = 'Lgraph — Визуальная карта архитектуры и контрактов'; "
        "$sc.Save(); "
        "Write-Output $lnkPath"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        env=ps_env,
        capture_output=True,
        text=True,
        check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    shortcut_out = proc.stdout.strip().splitlines()[-1].strip()
    return (Path(shortcut_out) if shortcut_out else None), cli_path


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    build_multi_size_ico(LOGO_PNG_PATH, LOGO_ICO_PATH)
    print(f"[OK] Сгенерирована многослойная иконка: {LOGO_ICO_PATH} ({LOGO_ICO_PATH.stat().st_size} байт)")
    lnk, cli = create_desktop_shortcut_and_cli()
    if lnk:
        print(f"[OK] Создан ярлык на Рабочем столе: {lnk}")
    if cli:
        print(f"[OK] Зарегистрирована быстрая команда терминала `lgraph`: {cli}")


if __name__ == "__main__":
    main()
