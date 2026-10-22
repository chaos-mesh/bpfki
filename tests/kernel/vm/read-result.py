#!/usr/bin/env python3

import base64
import io
import json
from pathlib import Path
import sys
import tarfile


def main():
    output = Path(sys.argv[1])
    log = (output / "serial.log").read_text(errors="replace").replace("\r", "")
    begin, end = "\nBPFKI_EVIDENCE_BEGIN\n", "BPFKI_EVIDENCE_END\n"
    if log.count(begin) != 1 or log.count(end) != 1:
        raise ValueError("guest did not return one complete evidence archive")
    encoded = log.split(begin)[1].split(end)[0]
    archive = base64.b64decode("".join(encoded.splitlines()), validate=True)
    evidence = output / "guest"
    evidence.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        if sum(item.size for item in source.getmembers()) > 128 * 1024 * 1024:
            raise ValueError("guest evidence exceeds 128 MiB")
        source.extractall(evidence, filter="data")
    result = json.loads((evidence / "vm-result.json").read_text())
    code = result["exit_code"]
    if type(code) is not int or not 0 <= code <= 255:
        raise ValueError("invalid guest exit code")
    environments = list(evidence.glob("bpfki-kernel-*/environment.json"))
    summaries = list(evidence.glob("bpfki-kernel-*/summary.json"))
    if len(environments) != 1 or len(summaries) != 1:
        raise ValueError("guest qualification or test summary is missing")
    environment = json.loads(environments[0].read_text())
    summary = json.loads(summaries[0].read_text())
    if code == 0 and (environment["outcome"] != "qualified" or summary.get("passed") is not True):
        raise ValueError("guest success disagrees with its qualification or test summary")
    qemu_code = int((output / "qemu-exit-code.txt").read_text())
    if not 0 <= qemu_code <= 255:
        raise ValueError("invalid QEMU exit code")
    result.update(acceleration=(output / "acceleration.txt").read_text().strip(),
                  kernel=environment["kernel"], qemu_exit_code=qemu_code,
                  passed=code == 0 and qemu_code == 0)
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
