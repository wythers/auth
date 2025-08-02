# Modern Auth Framework for Gin

A modern authentication framework for Gin, inspired by and reimagined from Authboss.

## Why This Project?

While [Authboss](https://github.com/volatiletech/authboss) is a powerful and well-designed authentication framework, it has two significant limitations when used in modern web development:

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

- 🔐 Full JWT support
- 🌐 RESTful API design for SPA consumption
- ⚡ Native Gin middleware and handlers
- 🔄 Event-driven architecture
- 🛡️ Modern security practices
- 📱 Multi-device support
- 🔑 OAuth2 integration
- ✉️ Email verification and password recovery
- 🔒 Rate limiting and brute force protection