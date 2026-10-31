# ⚡ EnvHub – Secure Team Configs

**A Secure, Encrypted Environment Variable Management Platform for Development Teams**

> Manage, encrypt, share, and organize environment variables across multiple projects and environments — all from one dashboard.

---

## 📌 1. Project Overview

EnvHub is a secure environment variable management platform designed to help developers and development teams store and manage sensitive configuration data in one centralized place.

During software development, developers frequently work with sensitive information such as:

- Database URLs
- API keys
- Authentication tokens
- JWT secrets
- Application passwords
- Third-party service credentials

Normally, developers store these values in `.env` files. However, sharing these files between team members can create security risks.

**EnvHub solves this problem by providing a centralized platform where environment variables can be securely stored, encrypted, and shared with authorized team members.**

It also provides role-based access control, activity logs, bulk imports, and CLI integration.

---

## 🎯 2. Problem Statement

Software development teams often face difficulties managing environment variables.

Some common problems include:

1. **Security Risks:** Sensitive API keys and passwords can accidentally be exposed through shared files or repositories.
2. **Team Collaboration:** Sharing `.env` files between multiple developers is inconvenient.
3. **Environment Confusion:** Managing separate development, staging, and production configurations can become difficult.
4. **Access Management:** Not every team member should have permission to modify sensitive configurations.
5. **Tracking Changes:** Developers often cannot easily identify who modified an environment variable.
6. **Manual Work:** Copying and updating environment variables manually wastes development time.

### Our Solution

EnvHub provides a centralized and encrypted workspace where developers can manage environment variables securely and collaborate with their teams.

---

## 💡 3. Key Features

### 🔐 1. Secure Authentication
- User registration and login.
- Email and password-based authentication.
- JWT-based session management.
- Individual user API keys.

### 🔒 2. Environment Variable Encryption
- AES-256-GCM encryption for stored variable values.
- HKDF-based blind indexing for secure key lookup.
- Sensitive values remain hidden by default.
- Reveal and hide variable values when required.

### 📁 3. Multiple Project Management
- Create multiple projects.
- Each project gets a unique Project ID.
- Switch between different projects.
- Manage configurations independently.

### 🌍 4. Multiple Environments

EnvHub supports three environments:

| Environment | Purpose |
|---|---|
| Development | Local development and testing |
| Staging | Pre-production testing |
| Production | Live application configuration |

Each environment can maintain its own set of variables.

### 👥 5. Team Collaboration

Invite team members to collaborate on projects.

EnvHub supports four roles:

| Role | Permissions |
|---|---|
| Owner | Complete project control |
| Admin | Manage team members and permissions |
| Editor | Add, edit, and delete variables |
| Viewer | Read-only access |

### 📜 6. Activity & Audit Logs

Track important project activities, including:

- Environment variable modifications.
- CLI configuration pulls.
- Team role changes.
- Other recorded project actions.

### 📥 7. Bulk Import

- Import multiple environment variables at once.
- Paste existing `.env` file contents.
- Automatically ignore comment lines.
- Update existing variables.

Example:

```env
PORT=3000
DATABASE_URL=mongodb://localhost:27017/myapp
JWT_SECRET=my_secret_key
NODE_ENV=development
