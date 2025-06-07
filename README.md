# JWT Authentication in JWT bearer ASP.Net Core

![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)
![C#](https://img.shields.io/badge/C%23-239120?logo=c-sharp&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?logo=JSON%20web%20tokens&logoColor=white)

A secure and scalable authentication system built with ASP.NET Core MVC that implements JSON Web Tokens (JWT) for stateless authentication.

## 📋 Table of Contents
- [Lý thuyết](#-lý-thuyết)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Yêu cầu hệ thống](#-yêu-cầu-hệ-thống)
- [Cấu hình](#-cấu-hình)
- [Tạo cơ sở dữ liệu](#-tạo-cơ-sở-dữ-liệu)
- [Sử dụng](#-sử-dụng)


## 📚 Lý thuyết

### JWT là gì?
JWT (JSON Web Token) là một tiêu chuẩn mở (RFC 7519) định nghĩa cách truyền thông tin một cách an toàn giữa các bên dưới dạng đối tượng JSON. Mỗi token chứa chữ ký số để xác thực tính toàn vẹn của thông tin.

### Các thành phần của JWT

Một JWT token bao gồm 3 phần chính, mỗi phần được phân cách bởi dấu chấm (.) và được mã hóa base64url:

```
xxxxx.yyyyy.zzzzz
```
![Cấu trúc JWT](https://cdn.auth0.com/blog/legacy-app-auth/legacy-app-auth-5.png)
1. **Header** (Phần đầu) - `xxxxx`
   - Chứa thông tin về loại token (JWT)
   - Thuật toán mã hóa (thường là HS256 hoặc RS256)
   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```

2. **Payload** (Phần thân) - `yyyyy`
   - Chứa các claims (thông tin về người dùng và dữ liệu bổ sung)
   - Có 3 loại claims: registered, public, và private
   ```json
   {
     "sub": "1234567890",
     "name": "John Doe",
     "admin": true,
     "iat": 1516239022
   }
   ```

3. **Signature** (Chữ ký) - `zzzzz`
   - Được tạo bằng cách mã hóa:
     - Header (base64url encoded)
     - Payload (base64url encoded)
     - Một secret key
   - Công thức: 
     ```
     HMACSHA256(
       base64UrlEncode(header) + "." +
       base64UrlEncode(payload),
       secret)
     ```

#### Ví dụ JWT thực tế:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

- **Phần màu đỏ**: Header
- **Phần màu tím**: Payload
- **Phần màu xanh dương**: Signature

### Luồng xác thực
1. Người dùng gửi thông tin đăng nhập
2. Server xác thực thông tin
3. Nếu hợp lệ, server tạo JWT và gửi về client
4. Client lưu token và gửi kèm trong các request tiếp theo
5. Server xác thực token trước khi xử lý yêu cầu

## 🗂️ Cấu trúc dự án

```
JwtAuth/
├── Controllers/           # Các controller xử lý request
│   ├── AuthController.cs    # Xử lý đăng nhập, đăng ký
│   └── HomeController.cs    # Trang chủ và các trang tĩnh
├── Models/                 
│   ├── Entities/           
│   │   ├── JwtAuthContext.cs # DbContext
│   │   └── User.cs          # Model người dùng
│   └── ErrorViewModel.cs    # Model thông báo lỗi
├── Services/               
│   ├── AuthService.cs      # Xử lý logic xác thực
│   └── JwtService.cs       # Xử lý tạo và xác thực JWT
├── Program.cs              # Cấu hình ứng dụng
└── appsettings.json        # Cấu hình ứng dụng
```

## 💻 Yêu cầu hệ thống

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
- [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) hoặc [VS Code](https://code.visualstudio.com/)

## ⚙️ Cấu hình

Chỉnh sửa file `appsettings.json` để cấu hình kết nối database và JWT:

```json
{
  "ConnectionStrings": {
    "Connection": "Server=...;Database=JwtAuthDB;User ID=...;Password=...;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True"
  },
  "JwtSettings": {
    "Secret": "a#28kdiUu38J@Ls93nfd8s9AJD*&^@!jd90213jfsdk!#@ksdf9JLs@!#d",
    "Issuer": "JwtAuthenticationServer",
    "Audience": "JwtAuthenticationClient",
    "ExpirationMinutes": "3"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

## 🗄️ Tạo cơ sở dữ liệu

1. **Tạo database**

   ```sql
   CREATE DATABASE JwtAuthDB;
    GO

    USE JwtAuthDB;
    GO

    CREATE TABLE Users (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Username NVARCHAR(50) NOT NULL,
        Email NVARCHAR(100) NOT NULL,
        PasswordHash VARBINARY(MAX) NOT NULL,
        PasswordSalt VARBINARY(MAX) NOT NULL,
        Role NVARCHAR(MAX) NOT NULL DEFAULT 'User',
        CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE()
    );
   ```

## 🎮 Sử dụng

### Đăng ký tài khoản mới
1. Truy cập `/Auth/Register`
2. Điền thông tin đăng ký
3. Nhấn "Đăng ký"

### Đăng nhập
1. Truy cập `/Auth/Login`
2. Nhập thông tin đăng nhập
3. Hệ thống sẽ lưu JWT vào cookie
4. Tự động chuyển hướng về trang chủ

---

<div align="center">
  <p>Được tạo bởi [NP-Sinh]</p>
</div>