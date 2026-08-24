# One device, two versions of the same library. Patching one leaves the other exposed.
Output assets/duplicates.gif

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 800
Set Padding 24
Set TypingSpeed 40ms

Hide
Type "cd /tmp/felfdemo && clear" Enter
Show

Type "# Netgear R7000. syft reports 3 components." Sleep 1s Enter
Sleep 800ms

Type "./felf scan r7000.chk | head -20" Sleep 500ms Enter
Sleep 7s

Type "# two copies of openssl, curl and zlib at different versions" Sleep 1s Enter
Sleep 2500ms
