# Pronet Fleet

مدیریت جفت‌سازی، سنجش خودکار و نگهداری تونل بین سرور ایران و خارج.

## نصب سریع

روی هر سرور (ایران، خارج، و سروری که مرکز روی آن است) اجرا کن:

```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash
```

اسکریپت نسخهٔ ثابت‌شده را از Releases دانلود می‌کند، **هش SHA256 را قبل از نصب بررسی می‌کند**، پیش‌نیازها را نصب می‌کند و منو را باز می‌کند.
اگر نسخهٔ قبلی نصب باشد، به‌جای نصب تازه ارتقا انجام می‌دهد و تونل‌های فعال را نگه می‌دارد.

### اگر GitHub از سرور ایران باز نمی‌شود

فایل `pronet-fleet-0.2.4.zip` را از بخش Releases روی سرور خارج یا کامپیوتر خودت بگیر و با scp به سرور ایران ببر. بعد این را اجرا کن:

```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh -o get.sh
sudo PRONET_ZIP=/root/pronet-fleet-0.2.4.zip bash get.sh
```

اگر raw.githubusercontent هم باز نمی‌شود، خود `get.sh` را هم با scp ببر.

## ترتیب راه‌اندازی

1. روی سرور ایران: `sudo pronet` و گزینهٔ **3) مرکز هماهنگی** را بزن. فایل `/etc/pronet-fleet/pronet-bootstrap.json` ساخته می‌شود.
2. این فایل را با scp روی هر دو سرور کپی کن. این فایل محرمانه است و نباید در GitHub قرار بگیرد.
3. روی ایران و خارج: `sudo pronet` و نقش هر سرور را انتخاب کن.
4. روی ایران «ساخت اتصال جدید» را بزن تا کد چهاررقمی بگیری. روی خارج `sudo pronet join <کد>` را اجرا کن.
5. پیشرفت را با `sudo pronet watch` ببین.

راهنمای کامل در `OPERATOR.fa.md` داخل بسته است و تغییرات این نسخه در `CHANGES-0.2.4.fa.md`.
