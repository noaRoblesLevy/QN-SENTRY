# Report fonts

DejaVu Sans and DejaVu Sans Mono 2.37 (https://github.com/dejavu-fonts/dejavu-fonts), used by the PDF report (#17).

The built-in PDF fonts (Helvetica, Courier) only cover Latin characters, so a homoglyph lookalike such as `bаdsecurityinc.be` with a Cyrillic `а` would be printed as `b■dsecurityinc.be`. DejaVu covers Latin, Greek and Cyrillic, the scripts homoglyphs come from. The fonts are bundled so the report looks the same in Docker and on every development machine.

License: see `LICENSE` (Bitstream Vera and Arev licenses, free to redistribute with the software).
