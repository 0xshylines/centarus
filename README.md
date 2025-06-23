# centarus v1
.NET derlemelerindeki (DLL/EXE) gömülü gizli anahtar, şifre, connection string vb. bilgileri decompiler kullanmadan bulur.

# Nasıl Kullanılır 

python centarus.py --help

centarus.py [-h] [--patterns PATTERNS] [--output OUTPUT] [--recursive] targets [targets ...]

positional arguments:
  targets               Taranacak dosya veya klasörler

options:
  -h, --help            show this help message and exit
  --patterns PATTERNS, -p PATTERNS
                        Özel pattern dosyası (varsayılan regex seti yerine)
  --output OUTPUT, -o OUTPUT
                        findings.csv veya findings.json olarak rapor dosyası
  --recursive, -r       Klasörleri alt dizinleriyle birlikte tara
