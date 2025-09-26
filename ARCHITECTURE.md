
# HiveMatrix Architecture & AI Development Guide

**Version 2.0**

## 1. Core Philosophy & Goals

This document is the single source of truth for the HiveMatrix architecture. Its primary audience is the AI development assistant responsible for writing and maintaining the platform's code. Adherence to these principles is mandatory.

Our goals are, in order of priority:

1.  **AI Maintainability:** The entire system is designed to be understood and modified by an AI. This means each individual application codebase (e.g., the entire `Resolve` application) **must** remain small, focused, and simple. We sacrifice some traditional development conveniences to achieve this.
    
2.  **Modularity:** The platform is a collection of small, independent, and fully functional applications that can be composed together. This allows for independent updates, deployments, and fault isolation.
    
3.  **Simplicity:** We favor simple, explicit patterns over complex, "magical" ones. If there is a choice between a clever one-line solution and a verbose five-line one, choose the latter.
    

## 2. Backend: The Monolithic Service Pattern

Each module in HiveMatrix (e.g., `Resolve`, `Architect`) is a **self-contained, monolithic application**. Each application is a single, deployable unit responsible for its own business logic, database, and UI rendering.

### Service Overview

-   **Core (IAM):** The security backbone. Handles all user and service authentication. Issues JWTs for all other services to consume.
    
-   **Nexus (UI Compositor & Proxy):** The user-facing gateway. Its primary role is to act as a smart reverse proxy that assembles the final UI for the user. It contains no business logic of its own.
    
-   **Codex (CRM):** A complete application for managing clients, contacts, and assets.
    
-   **Architect (Project Management):** A complete application for managing projects, tasks, and timelines.
    
-   **KnowledgeTree (Wiki):** A complete application for the hierarchical knowledge base.
    
-   **Resolve (Ticketing):** A complete application for the AI-first ticketing system.
    
-   **Brainhair (AI Processor):** Pluggable interface for connecting to various AI models.
    
-   **Tracker (Order Tracking):** A complete application for managing client procurement.
    
-   **Ledger (Billing):** A complete application for aggregating billing information.
    

### AI Instructions for Application Development

-   **Server-Side Rendering:** Applications **must** render their user interfaces on the server side. They will have web endpoints (e.g., `/tickets/view/123`) that return complete HTML documents.
    
-   **Data APIs:** Applications may _also_ expose data-only APIs (e.g., `/api/tickets`) that return JSON for automation or future needs.
    
-   **Data Isolation:** Each service owns its own database. You are forbidden from accessing another service's database directly. You must always go through its public API if one is available.
    
-   **Authentication:** All inter-service communication and access to protected UI routes must be authenticated. Services will validate a JWT issued by **Core**.
    

## 3. Frontend: UI Composition via Smart Proxy

The HiveMatrix user interface is not a single JavaScript application. It is a **composition** of multiple, independent, server-rendered applications presented to the user through the `Nexus` proxy.

### The Golden Rule of Styling

**Applications are forbidden from containing their own styling.**

This means:

-   No `.css`, `.scss`, or `.less` files.
    
-   No `<style>` blocks in HTML templates.
    
-   No inline `style="..."` attributes.
    

Applications are responsible for **structure (HTML)** and **logic (Python, etc.)** only. All visual presentation is handled exclusively by `Nexus`.

### The `Nexus` UI Composition Model

1.  A user navigates to `https://hivematrix.com/resolve/tickets`.
    
2.  The request hits **`Nexus`**.
    
3.  `Nexus` proxies the request to the internal `Resolve` application.
    
4.  The `Resolve` application processes the request, queries its database, and renders a complete, but **unstyled**, HTML page.
    
5.  `Resolve` returns the unstyled HTML back to `Nexus`.
    
6.  `Nexus` receives the HTML. Before sending it to the user, it **injects the global stylesheet** into the `<head>` tag of the document.
    
7.  The final, styled HTML is sent to the user's browser.
    

### Development Workflow Mandate

An application must be fully functional when accessed directly (e.g., at its internal IP/port). It will appear unstyled. To finalize a feature or debug a layout, you must test it by accessing it through the `Nexus` URL.

## 4. The HiveMatrix Design System & CSS

To ensure a consistent user experience, all styling is controlled by a single, global stylesheet located in `Nexus`. To prevent class name conflicts, we use the **BEM (Block, Element, Modifier)** naming convention.

**You must adhere to this convention strictly.**

### BEM Naming Convention

-   **Block:** A standalone, reusable component. `Examples: .card, .btn, .form-field`
    
-   **Element:** A part of a block. Its name is formed by `block-name__element-name`. `Examples: .card__title, .btn__icon, .form-field__label`
    
-   **Modifier:** A flag that changes the state or appearance of a block or element. Its name is formed by `block-name--modifier-name` or `block-name__element-name--modifier-name`. `Examples: .btn--danger, .form-field--has-error`
    

### Example: Creating a Button

**1. AI Task: "Create a red 'Delete' button for a ticket in `Resolve`."**

**2. AI Action: Consult this document for the `btn` component.**

```
### Component: Button (`btn`)

**Block:** `.btn`
The base class for all button elements.

**Elements:**
- `.btn__icon`: For an icon inside a button.
- `.btn__label`: For the text label of a button.

**Modifiers:**
- `.btn--primary`: For the main call-to-action.
- `.btn--danger`: For destructive actions (e.g., delete).
- `.btn--disabled`: For disabled or inactive buttons.

```

**3. AI Action: Write the HTML template in the `Resolve` application using the correct BEM classes.**

```
<!-- INCORRECT: Does not use BEM -->
<button class="delete-button">Delete Ticket</button>

<!-- CORRECT: Uses the defined BEM structure -->
<button class="btn btn--danger">
  <span class="btn__label">Delete Ticket</span>
</button>

```

By following this pattern, the HTML generated by the `Resolve` application is simple and semantic. The visual appearance (`color: red`, etc.) is applied automatically by the global stylesheet injected by `Nexus`.
