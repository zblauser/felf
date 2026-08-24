# Recording the demos

Tapes expect a demo directory at `/tmp/felfdemo` containing `dir-655.bin`, `r7000.chk`,
the `felf` binary and `show-evidence.sh`. macOS clears `/tmp`, so rebuild it first:

```sh
mkdir -p /tmp/felfdemo && cd /tmp/felfdemo
unzip -o -q "$HOME/fwcorpus/vendor/dlink-dir-655-DIR-655_REVC_FIRMWARE_3.02.B05.ZIP"
unzip -o -q "$HOME/fwcorpus/vendor/netgear-r7000.zip"
mv DIR655C1_FW302B05.bin dir-655.bin
mv R7000-V1.0.11.136_10.2.120.chk r7000.chk
rm -f *.PDF *.html
cp <repo>/target/release/felf .
printf '#!/usr/bin/env bash\njq %s "$1"\n' \
  "'[.components[] | select(.name==\"openssl\")][0] | {name, version, cpe, evidence: .evidence.identity[0].methods[0:3]}'" \
  > show-evidence.sh && chmod +x show-evidence.sh
```

Then from the repo root: `vhs assets/tapes/extract.tape` (and `duplicates`, `report`).

`extract.tape` depends on `binwalk` failing on the LZMA1 image — that failure is the point
of the demo. If binwalk ever gains working `sasquatch` support locally, the GIF stops
telling the story and the tape needs rewording.
