# The headline: binwalk sees the filesystem and cannot open it. felf reads it.
Output assets/extract.gif

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 760
Set Padding 24
Set TypingSpeed 40ms

Hide
Type "cd /tmp/felfdemo && clear" Enter
Show

Type "# D-Link DIR-655 firmware, straight from the vendor" Sleep 1s Enter
Sleep 800ms

Type "binwalk -e dir-655.bin 2>&1 | tail -4" Sleep 500ms Enter
Sleep 4s

Type "# binwalk finds the filesystem, then cannot extract it" Sleep 1s Enter
Sleep 1500ms

Type "./felf scan dir-655.bin" Sleep 500ms Enter
Sleep 6s
