# Zoraxy CI/CD Integrator

Plugin Go untuk membuat, mengubah upstream, dan menghapus **host-based HTTP reverse proxy** Zoraxy melalui pipeline CI/CD. Memakai kontrak `-introspect` / `-configure` [Zoraxy Plugin API](https://zoraxy.aroz.org/plugins/html/zoraxy_plugin%20API.html) dan API manajemen Zoraxy. Tidak memasang sertifikat, DNS, atau deploy aplikasi secara otomatis.

> **Perhatian:** API plugin bearer-token Zoraxy tidak menyediakan pembuatan/penghapusan rule. Plugin ini login ke **API manajemen** memakai akun admin + CSRF untuk operasi tersebut. Simpan kredensial dan token dengan aman; jangan expose endpoint CI/CD ke internet tanpa HTTPS. Zoraxy management port harus privat.

## Menjalankan

Memerlukan Go 1.22+. Build untuk OS/arsitektur **server Zoraxy** (contoh Linux amd64):

```sh
GOOS=linux GOARCH=amd64 go build -o dist/zoraxy-integrator .
```

Buat folder plugin bernama `zoraxy-integrator` di folder plugin Zoraxy, isi executable `zoraxy-integrator` serta file `integrator.json`; berikan izin eksekusi pada binary. Zoraxy menemukan executable yang namanya sama dengan folder dan menjalankannya dengan `-introspect` dan `-configure`. Aktifkan plugin di pengelola plugin Zoraxy. Metadata bisa dicek manual dengan `./dist/zoraxy-integrator -introspect`.

Siapkan `integrator.json` dari `integrator.example.json`, ganti semua nilai contoh. `allowed_domains` wajib diisi; hostname harus sama dengan domain atau subdomainnya. Buat token acak **minimal 32 karakter**, misalnya dengan `openssl rand -hex 32`. Restriksi akses file konfigurasi (mis. `chmod 600 integrator.json`), jangan commit secrets. Lingkungan plugin dapat diisi via `ZORAXY_URL`, `ZORAXY_USERNAME`, `ZORAXY_PASSWORD`, `INTEGRATOR_TOKEN`, dan `INTEGRATOR_ALLOWED_DOMAINS` (daftar domain dipisahkan koma). Environment menimpa file. Zoraxy management URL default `http://127.0.0.1:8000` dan harus dapat diakses dari proses plugin; gunakan HTTPS jika melintasi jaringan tidak tepercaya. Akun Zoraxy harus memiliki sesi login yang berfungsi (jangan andalkan mode `-noauth`).

Untuk pengujian tanpa Zoraxy plugin manager: `go run . -listen 127.0.0.1:9080 -config integrator.json`. Endpoint langsung berjalan di alamat itu. Ketika dipasang sebagai plugin, endpoint yang sama diteruskan melalui **proxy rule yang mengaktifkan plugin** pada prefix `/_zoraxy-integrator/v1/`. Jangan mengaktifkan plugin untuk proxy rule publik yang tidak dipercaya: host allowlist melindungi target yang dimodifikasi, bukan siapa yang dapat mencoba mengakses endpoint. Gunakan host khusus yang dilindungi HTTPS dan kontrol akses (atau panggil listener lokal dari job CI pada mesin yang sama). Jangan bocorkan token dalam log/artifact pipeline. Perhatikan bahwa `UIPath` hanya menampilkan petunjuk; tidak menyimpan secrets.

## API CI/CD

Semua permintaan memerlukan `Authorization: Bearer <token>`. `PUT` dan `DELETE` memerlukan `Content-Type: application/json` serta body tunggal. Gunakan alamat plugin yang dapat dicapai pipeline:

```sh
curl -fsS -X PUT https://integrator.example.com/_zoraxy-integrator/v1/proxies \
  -H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' \
  -d '{"hostname":"app.apps.example.com","upstream":"http://10.0.0.5:8080"}'

curl -fsS -X DELETE https://integrator.example.com/_zoraxy-integrator/v1/proxies \
  -H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' \
  -d '{"hostname":"app.apps.example.com"}'
```

`upstream` wajib berbentuk `http://host:port` atau `https://host:port`, tanpa path/query/userinfo. Skema menentukan TLS **ke upstream**; TLS publik/dari klien diatur terpisah dalam Zoraxy. Respons JSON: `{"action":"created|updated|unchanged|deleted","hostname":"...","upstream":"..."}`. `GET /_zoraxy-integrator/v1/health` (tetap perlu token) mengembalikan `{"status":"ok"}`.

Plugin membuat rule dengan tag `zoraxy-integrator` dan hanya akan mengubah/menghapus rule yang memiliki tag tersebut. Jika rule host telah ada tetapi bukan milik plugin, permintaan gagal, bukan menimpanya. Untuk perubahan upstream plugin hanya mendukung rule aktif dengan **tepat satu upstream aktif dan tanpa upstream nonaktif**, dan mempertahankan pengaturan rule lainnya. `DELETE` untuk hostname yang belum ada menghasilkan `unchanged`. Operasi dibaca ulang setelah mutasi; kegagalan mengembalikan HTTP 502. Bila 502 terjadi, periksa kondisi rule di Zoraxy sebelum mengulang deploy: API Zoraxy tidak bersifat transaksional. Proses terpisah / job CI bersamaan tidak mendapat penguncian lintas-proses; serialisasikan deploy per hostname.

## Contoh GitHub Actions

Tambahkan step berikut **setelah deployment aplikasi berhasil**. Simpan `INTEGRATOR_URL` (mis. `https://integrator.example.com`) dan `INTEGRATOR_TOKEN` sebagai repository secrets; isi repository variables `APP_HOSTNAME` dan `APP_UPSTREAM`. Runner harus dapat mengakses integrator, dan Zoraxy harus dapat mengakses upstream. Contoh memakai `jq` yang tersedia di runner Ubuntu GitHub-hosted.

```yaml
concurrency:
  group: production-proxy
  cancel-in-progress: false

jobs:
  proxy:
    runs-on: ubuntu-latest
    steps:
      - name: Apply Zoraxy proxy
        env:
          INTEGRATOR_URL: ${{ secrets.INTEGRATOR_URL }}
          INTEGRATOR_TOKEN: ${{ secrets.INTEGRATOR_TOKEN }}
          APP_HOSTNAME: ${{ vars.APP_HOSTNAME }}
          APP_UPSTREAM: ${{ vars.APP_UPSTREAM }}
        run: |
          set -eu
          jq -n --arg hostname "$APP_HOSTNAME" --arg upstream "$APP_UPSTREAM" \
            '{hostname: $hostname, upstream: $upstream}' > payload.json
          curl --fail-with-body --silent --show-error --max-time 60 \
            -X PUT "${INTEGRATOR_URL}/_zoraxy-integrator/v1/proxies" \
            -H "Authorization: Bearer ${INTEGRATOR_TOKEN}" \
            -H 'Content-Type: application/json' \
            --data-binary @payload.json
```

`curl` exit nonzero pada respons 4xx/5xx sehingga job gagal. Jangan menambahkan retry otomatis untuk mutasi tanpa mengecek state setelah error.

## Validasi

```sh
go test -race ./...
go vet ./...
```

Referensi kontrak CRUD Zoraxy yang dipakai: [proxy handler](https://github.com/tobychui/zoraxy/blob/main/src/reverseproxy.go), [upstream handler](https://github.com/tobychui/zoraxy/blob/main/src/upstreams.go). API manajemen Zoraxy tidak dijamin stabil lintas versi; uji di staging sebelum penggunaan produksi.
