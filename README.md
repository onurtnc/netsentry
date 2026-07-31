# NetSentry

**PCAP dosyalarinda C2 beacon, DNS tuneli, tarama ve veri sizintisi arayan — sifir bagimlilikli ag analiz araci.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-18%20passing-success)

`scapy`, `dpkt`, `pyshark` ya da Wireshark kurulumu gerektirmez. PCAP/PCAPNG cozucusu,
Ethernet/IP/TCP/UDP/DNS/HTTP/TLS ayristiricisi ve dokuz dedektor tamamen Python
standart kutuphanesiyle yazilmistir.

---

## Neden?

Wireshark harika bir arac ama "bu yakalamada kotu bir sey var mi?" sorusuna cevap
vermez — filtreleri sizin yazmaniz gerekir. NetSentry bu ilk gecisi otomatiklestirir:
akislari cikarir, davranissal analizleri calistirir ve size **onceliklendirilmis bir
bulgu listesi** verir. Wireshark'i sonra, hangi akisa bakacaginizi bilerek acarsiniz.

## Tespit yetenekleri

| Kod | Bulgu | Nasil calisir |
|---|---|---|
| `NS-BEACON` | **C2 beacon** | Ayni hedefe tekrarlanan baglantilarin aralik varyansi (jitter) olculur. Makine uretimi beacon'lar cok duzenlidir; insan trafigi degildir. DNS/NTP gibi dogal periyodik protokoller haric tutulur. |
| `NS-DNSTUN` | **DNS tunelleme** | Alt alan adi uzunlugu, Shannon entropisi, benzersiz alt alan orani ve TXT/NULL sorgu yogunlugu birlikte puanlanir. |
| `NS-DGA` | **DGA alan adlari** | Yuksek entropi + dusuk sesli harf orani + rakam yogunlugu ile algoritma uretimi alan adlari. |
| `NS-PORTSCAN` | **Port taramasi** | Tek kaynaktan cok sayida yanitsiz SYN. |
| `NS-SWEEP` | **Host sweep** | Tek kaynaktan cok sayida farkli hedefe baglanti denemesi. |
| `NS-EXFIL` | **Veri sizdirma** | Tek harici hedefe giden hacim ve giden/gelen bayt orani. |
| `NS-BADPORT` | **Supheli portlar** | 4444 (Metasploit), 1337, 31337, 6667 (IRC C2), Tor, madenci havuz portlari. |
| `NS-CLEARAUTH` / `NS-FTPCLEAR` / `NS-TELNET` | **Sifresiz kimlik bilgisi** | HTTP `Authorization`, FTP `USER/PASS`, Telnet oturumlari. |
| `NS-EXEDL` | **HTTP ile exe indirme** | Sifresiz HTTP uzerinden `.exe/.dll/.ps1/.hta` talebi. |
| `NS-BADUA` | **Otomatik arac trafigi** | `curl`, `python-requests`, `powershell`, `sqlmap` gibi User-Agent'lar veya UA'sizlik. |
| `NS-BADTLD` | **Riskli TLD** | `.top`, `.xyz`, `.zip`, `duckdns.org`, `ngrok.io` gibi hedefler (HTTP Host + TLS SNI). |
| `NS-ICMPTUN` | **ICMP tuneli** | 128 bayti asan ICMP yukleri. |

Ayrica cikarilan meta veri: DNS sorgu listesi, HTTP istekleri, **TLS SNI alan adlari**,
akis tablosu, en cok konusan kaynaklar.

## Kurulum

```bash
git clone https://github.com/<kullanici>/netsentry.git
cd netsentry
python -m netsentry samples/ornek_trafik.pcap
```

Komut olarak eklemek icin: `pip install -e .`

## Kullanim

```bash
# Temel analiz
python -m netsentry capture.pcap

# HTML + JSON rapor
python -m netsentry capture.pcapng --html rapor.html --json bulgular.json

# Sadece meta veri dok (grep/awk ile isleyebilirsiniz)
python -m netsentry capture.pcap --dns
python -m netsentry capture.pcap --http
python -m netsentry capture.pcap --flows

# Hassasiyet ayari
python -m netsentry capture.pcap --beacon-jitter 0.30 --beacon-min-events 4
python -m netsentry capture.pcap --exfil-mb 50

# CI / otomasyon
python -m netsentry capture.pcap --fail-on high --quiet
```

### Ornek cikti

```
==============================================================================
  NetSentry - Ag Trafigi Analiz Raporu
==============================================================================
  Paket    : 1158   Veri: 1.3 MB   Akis: 34
  Zaman    : 2026-07-25 17:20:00 - 2026-07-25 17:33:20 (799.6 sn)
  DNS      : 66 sorgu   HTTP: 2 istek   TLS: 26 SNI
  Risk     : [####################] 100/100   Bulgu: 12
------------------------------------------------------------------------------
[CRITICAL] Duzenli aralikli baglanti (olasi C2 beacon)
    10.0.0.23 adresi cdn-telemetry.top:443 hedefine 14 kez, ortalama 60.0
    saniye araliklarla baglandi (jitter %0.6).
      - aralik ornekleri: 59.7s, 60.3s, 60.0s, 59.5s, 59.9s, 60.4s
      - toplam veri: 6.5KB

[CRITICAL] DNS tunelleme / DNS uzerinden veri sizdirma
    'datatransfer.xyz' alan adina yapilan sorgular veri tasima deseni gosteriyor:
    ortalama alt alan uzunlugu 48 karakter; yuksek entropi (4.59 bit/karakter);
    46 farkli alt alan adi / 46 sorgu; 16 adet TXT/NULL sorgusu.
      - 23ztub1wgkfatmkmgfk9zpd1o0v934meeeixrybapd89hzr7.tun.datatransfer.xyz
```

## Ornek yakalama

`samples/ornek_trafik.pcap` **tamamen sentetiktir** — `tools/make_sample_pcap.py`
tarafindan uretilir, gercek bir agdan alinmamistir. Icinde bilerek yerlestirilmis
12 farkli senaryo vardir (normal web trafigi + her dedektor icin birer ornek).
Yeniden uretmek icin:

```bash
python tools/make_sample_pcap.py
```

Dosyayi kucuk tutmak icin buyuk transfer paketleri **kirpilmis** olarak kaydedilir
(`tcpdump -s` davranisi); orijinal paket boyu baslikta korundugu icin bayt
istatistikleri dogru kalir.

## Beacon tespiti nasil calisir?

```
aralıklar = [t2-t1, t3-t2, ...]
jitter    = stdev(aralıklar) / mean(aralıklar)
```

| jitter | yorum |
|---|---|
| < 0.08 | neredeyse mekanik duzen → **critical** |
| 0.08 - 0.15 | zayif rastgelelestirme eklenmis beacon → **high** |
| > 0.15 | normal uygulama/insan trafigi → raporlanmaz |

Gercek dunyada C2 cerceveleri jitter ekler (orn. Cobalt Strike `%20 jitter`).
`--beacon-jitter 0.35` ile esigi gevsetip daha genis tarama yapabilirsiniz —
yanlis pozitif sayisi artar ama gizlenmis beacon'lari yakalama sansiniz yukselir.

## Mimari

```
netsentry/
├── pcap.py     PCAP + PCAPNG okuyucu/yazici (saf struct)
├── decode.py   Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP, DNS, HTTP, TLS SNI
├── flows.py    Paket -> akis toplama, ic/dis ag ayrimi, istatistik
├── detect.py   Dokuz dedektor + Shannon entropi yardimcilari
├── report.py   Konsol / JSON / HTML ciktilari
└── cli.py      argparse arayuzu
tools/
└── make_sample_pcap.py   Sentetik ornek yakalama ureticisi
```

Desteklenen link tipleri: Ethernet (1), RAW IP (101), Linux cooked (113), NULL/loopback (0).

## Testler

```bash
python tools/make_sample_pcap.py     # ornek pcap'i uret
python -m unittest discover -s tests -v
```

Testler arasinda **"normal trafik beacon olarak isaretlenmemeli"** gibi yanlis
pozitif regresyon testleri de vardir.

## Yol haritasi

- [ ] JA3/JA3S TLS parmak izi
- [ ] TCP akis yeniden birlestirme (dosya cikarma)
- [ ] Zeek `conn.log` / `dns.log` disa aktarimi
- [ ] Canli arayuz dinleme modu (root gerektirir)
- [ ] IOCForge ile entegrasyon: bulunan IP/alan adlarini otomatik zenginlestirme
- [ ] IPv6 uzanti basliklarinin tam cozumu

## Sorumluluk reddi

Savunma amacli bir aractir. Sadece yakalamaya yetkili oldugunuz aglarda kullanin.
Bulgular otomatik karar degil, inceleme baslangicidir — ozellikle beacon ve DGA
tespitleri istatistikseldir ve yanlis pozitif uretebilir.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
