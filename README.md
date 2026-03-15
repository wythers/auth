<img src="http://i.imgur.com/fPIgqLg.jpg"/>  

# Modern Auth Middlewares for Gin

A modern authentication Middlewares for Gin, inspired by and reimagined from Authboss.

## Why This Project?

While [Authboss](https://github.com/volatiletech/authboss) is a mature and comprehensive modular authentication system with extensive features, it has two significant limitations when used in modern web development:

1. **Poor SPA Support**: 
   - Authboss is primarily designed for server-side rendering
   - It assumes traditional form submissions and page redirects
   - The workflow becomes cumbersome when serving Single Page Applications

2. **Complex Gin Integration**:
   - Integrating Authboss with Gin requires extensive adaptation
   - The middleware chain becomes unnecessarily complex
   - The natural flow of Gin's middleware pattern is disrupted

This project aims to solve these limitations by:
- Reimagining Authboss's robust features for modern SPA architectures
- Providing seamless integration with Gin framework
- Maintaining the powerful features while modernizing the implementation

## Key Features

- 🔐 Security cookie-based session management
- 🌐 JSON API responses with customizable formats
- ⚡  Native Gin middleware and handlers
- 🛡️ CSRF protection and security middleware
- 📧 Email verification and password recovery
- 🔒 Rate limiting and brute force protection
- 🔧 Modular architecture with customizable middleware
- 🎨 Flexible response handling via CollectMiddleware
- 📝 HTML and text email template rendering
- 🚀 Production-ready with structured logging
- 🔑 OAuth2 integration (TODO)
- 📱 Two-factor authentication with TOTP/SMS (TODO)
- 🤖 CAPTCHA support (Cloudflare Turnstile) (TODO)
- 🔐 One-time password (OTP) system (TODO)

## Quick Start

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/wythers/auth"
    "github.com/wythers/auth/login"
    "github.com/wythers/auth/register"
)

func main() {
    // Initialize auth engine
    authEngine := auth.New(
        auth.WithStorage(yourStorageImplementation),
        auth.WithMailer(yourMailerImplementation),
        auth.WithRenderer(yourRendererImplementation),
    )

    r := gin.Default()
    
    // Auth routes
    authGroup := r.Group("/auth", authEngine.AuthMiddlewares()...)
    {
        // Basic authentication endpoints
        authGroup.POST("/login", login.Handler[LoginRequest](authEngine)...)
        authGroup.POST("/register", register.Handler[RegisterRequest](authEngine)...)
        authGroup.POST("/logout", logout.Handler(authEngine))
    }

    r.Run(":8080")
}
```

## Architecture

This framework follows a modular design where each authentication feature is implemented as a separate module:

- **`login/`** - User login and session management
- **`register/`** - User registration and email confirmation
- **`recover/`** - Password recovery and reset
- **`nocsrf/`** - CSRF protection middleware
- **`limit/`** - Rate limiting functionality
- **`lock/`** - Account locking mechanisms
- **`mail/`** - Email sending and templating
- **`oauth2/`** - OAuth2 integration(TODO)
- **`otp/`** - One-time password system(TODO)
- **`captcha/`** - CAPTCHA support (Cloudflare Turnstile)(TODO)


## Documentation

For detailed documentation and examples, see the `_example/` directory which contains a complete working implementation.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.