# AnubisX Website - Incident Response Framework Platform

## Overview

AnubisX is a modern incident response framework website that centralizes detection rules, downloadable playbooks, and automated workflows into one accessible platform. The application serves SOC analysts, incident responders, threat hunters, security engineers, and cybersecurity students by providing comprehensive resources organized by MITRE ATT&CK mapping and detection languages. The platform features a modern, animated, and responsive design with client-side search and filtering capabilities, requiring no database dependency for core functionality.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
The application uses a modern React-based single-page application (SPA) architecture built with Vite as the build tool. The frontend leverages TypeScript for type safety and follows a component-based architecture with the following key decisions:

- **UI Framework**: Radix UI components with shadcn/ui for consistent, accessible design system
- **Styling**: Tailwind CSS with custom CSS variables for theming, supporting dark mode as default
- **Animation**: Framer Motion for smooth animations and transitions throughout the interface
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: React Query (@tanstack/react-query) for server state management
- **Search**: Fuse.js for client-side fuzzy searching across content
- **Form Handling**: React Hook Form with Zod validation

### Backend Architecture
The backend follows a minimal Express.js server architecture with the following design decisions:

- **Server Framework**: Express.js with TypeScript for the API layer
- **Development Setup**: Vite integration for hot module replacement in development
- **Static Content**: The platform primarily serves static content with detection rules, playbooks, and workflows stored as static data
- **Storage Interface**: Abstracted storage interface (IStorage) allowing for future database integration while currently using in-memory storage for user management

### Data Storage Strategy
The application implements a hybrid approach to data management:

- **Static Content**: Detection rules, playbooks, workflows, and team information are stored as static TypeScript data structures, enabling fast loading and client-side filtering without database queries
- **User Data**: Prepared for database integration with Drizzle ORM schema definitions and PostgreSQL configuration, though currently using in-memory storage
- **Session Management**: Ready for PostgreSQL session storage with connect-pg-simple

### Component Organization
The frontend follows a structured component hierarchy:

- **Page Components**: Route-specific components (Home, NotFound)
- **Feature Components**: Section-specific components (HeroSection, DetectionRules, IRPlaybooks, etc.)
- **UI Components**: Reusable design system components from shadcn/ui
- **Layout Components**: Navigation and Footer for consistent structure

### Search and Filtering
Client-side search functionality using Fuse.js provides:

- **Fuzzy Search**: Intelligent matching across titles and descriptions
- **Multi-Category Search**: Unified search across detection rules, playbooks, workflows, and team members
- **Filtered Results**: Category-specific filtering with visual indicators
- **Performance**: No server round-trips required for search operations

### Responsive Design
The application implements a mobile-first responsive design:

- **Breakpoint Strategy**: Tailwind CSS responsive utilities for consistent behavior across devices
- **Mobile Navigation**: Collapsible mobile menu with smooth animations
- **Touch Optimization**: Appropriate touch targets and gestures for mobile users
- **Performance**: Optimized animations that respect user motion preferences

## External Dependencies

### Core Framework Dependencies
- **React 18**: Modern React with hooks and concurrent features
- **Vite**: Fast build tool and development server with HMR
- **Express.js**: Minimal web server framework for API endpoints
- **TypeScript**: Type safety across the entire application stack

### Database and ORM
- **Drizzle ORM**: Type-safe database ORM with PostgreSQL dialect
- **@neondatabase/serverless**: Serverless PostgreSQL client (configured but not actively used)
- **connect-pg-simple**: PostgreSQL session store (prepared for future use)

### UI and Design System
- **Radix UI**: Accessible, unstyled UI components (@radix-ui/react-*)
- **Tailwind CSS**: Utility-first CSS framework with PostCSS
- **Framer Motion**: Animation library for smooth interactions
- **Lucide React**: Icon library for consistent iconography

### Development and Build Tools
- **Replit Integration**: Development environment plugins for cartographer and dev banner
- **ESBuild**: Fast JavaScript bundler for production builds
- **PostCSS**: CSS processing with Autoprefixer

### Utility Libraries
- **Fuse.js**: Client-side fuzzy search functionality
- **React Hook Form**: Form handling with validation
- **Zod**: Runtime type validation and schema definition
- **date-fns**: Date manipulation utilities
- **clsx & class-variance-authority**: Conditional CSS class management