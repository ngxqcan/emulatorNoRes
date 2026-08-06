import base64
import hashlib
import secrets
import sys

HT_SUFFIX = bytes.fromhex("F4AD529CDE170EE1D1029B4A3CA89820")
VG_VERSION = "1.18.4.47"


def rand_b64(n: int) -> str:
    return base64.b64encode(secrets.token_bytes(n)).decode("ascii")


def build_token6() -> str:
    hex_id = secrets.token_hex(8).upper()
    p = [hex_id[i:i + 4] for i in range(0, 16, 4)]
    prefix = f"0000_0000_0000_0000_{p[0]}_{p[1]}_{p[2]}_{p[3]}.SAMSUNG MZVL21T0"
    first = prefix.encode("ascii").ljust(97, b"\x00")
    zeros = b"\x00" * 97
    segs = [base64.b64encode(x).decode("ascii") for x in [first, zeros, zeros, zeros, zeros]]
    return ";".join(segs)


def compute_ht(machine_id: str) -> str:
    tokens: dict[str, str] = {}
    for part in machine_id.split("||"):
        if part:
            tokens[part[0]] = part
    concat = tokens["6"] + tokens["1"] + tokens["2"] + tokens["3"] + tokens["5"] + VG_VERSION
    digest = hashlib.sha1(concat.encode("ascii") + HT_SUFFIX).digest()
    return base64.b64encode(digest).decode("ascii")


def make_entry() -> tuple[str, str]:
    machine_id = (
        f"||1;{rand_b64(16)}"
        f"||2;{rand_b64(64)}"
        f"||3;{rand_b64(64)}"
        f"||4"
        f"||5;{rand_b64(6)}"
        f"||6;{build_token6()}"
    )
    return machine_id, compute_ht(machine_id)


def main() -> None:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 90000
    out_path = sys.argv[2] if len(sys.argv) > 2 else "output.txt"

    lines: list[str] = []
    for i in range(1, count + 1):
        mid, ht = make_entry()
        lines += [f"# {i}", f"machine_id={mid}", f"ht={ht}", ""]

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

    print(f"wrote {out_path}  ({count} entries)")


if __name__ == "__main__":
    main()