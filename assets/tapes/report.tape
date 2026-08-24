# The artifact: a CycloneDX SBOM whose claims carry their evidence.
Output assets/report.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 780
Set Padding 24
Set TypingSpeed 40ms

Hide
Type "cd /tmp/felfdemo && clear" Enter
Show

Type "./felf scan r7000.chk --baseline 3 --sbom r7000.cdx.json --report r7000.html | tail -3" Sleep 500ms Enter
Sleep 7s

Type "# every claim carries the evidence behind it" Sleep 1s Enter
Sleep 800ms

Type "./show-evidence.sh r7000.cdx.json" Sleep 500ms Enter
Sleep 6s
