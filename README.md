# Projexx - Collaborative Project Management Platform

A modern, full-stack project management platform designed for students and faculty to collaborate on academic projects.

## 🚀 Features

- **User Management**: Separate dashboards for students and faculty
- **Project Creation**: Faculty can create and manage projects
- **Team Management**: Students can form teams and join projects
- **Task Management**: Create, assign, and track tasks with deadlines
- **File Sharing**: Upload and share project files
- **Real-time Messaging**: Built-in chat system for team communication
- **Analytics Dashboard**: Comprehensive analytics for project progress
- **Grading System**: Faculty can grade student submissions
- **Calendar Integration**: Project deadlines and milestones

## 🛠️ Tech Stack

### Frontend
- **React 18** with modern hooks
- **Material-UI** for components
- **Tailwind CSS** for styling
- **React Router** for navigation
- **Axios** for API calls
- **Socket.io** for real-time features

### Backend
- **Node.js** with Express.js
- **MongoDB** with Mongoose
- **JWT** for authentication
- **Cloudinary** for file storage
- **Socket.io** for real-time communication

## 📁 Project Structure

```
projexx/
├── frontend/          # React frontend application
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API services
│   │   └── utils/         # Utility functions
│   └── package.json
├── backend/           # Node.js backend API
│   ├── routes/       # API routes
│   ├── models/       # Database models
│   ├── middleware/   # Custom middleware
│   └── package.json
├── vercel.json       # Vercel deployment configuration
└── package.json      # Root package.json for monorepo
```

## 🚀 Deployment

### Vercel (Frontend)
This project is configured for Vercel deployment:

- **Framework**: Create React App
- **Build Command**: `cd frontend && npm install && npm run build`
- **Output Directory**: `frontend/build`
- **Root Directory**: `frontend`

### Environment Variables
Make sure to set these environment variables in Vercel:

- `REACT_APP_API_BASE_URL`: Your backend API URL
- `REACT_APP_CLOUDINARY_CLOUD_NAME`: Cloudinary cloud name
- `REACT_APP_CLOUDINARY_UPLOAD_PRESET`: Cloudinary upload preset

## 🏃‍♂️ Quick Start

### Prerequisites
- Node.js (>=16.0.0)
- npm (>=8.0.0)
- MongoDB database

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/iwantdrugsxd/projexxx.git
   cd projexxx
   ```

2. **Install dependencies**
   ```bash
   npm run install:all
   ```

3. **Set up environment variables**
   - Copy `.env.example` to `.env` in both frontend and backend directories
   - Fill in your database and API keys

4. **Start development servers**
   ```bash
   npm run start:dev
   ```

### Available Scripts

- `npm start` - Start both frontend and backend
- `npm run start:dev` - Start both in development mode
- `npm run build` - Build frontend for production
- `npm run install:all` - Install all dependencies

## 📱 Usage

### For Faculty
1. Register/Login as faculty
2. Create project servers
3. Add students to servers
4. Create tasks and assignments
5. Grade student submissions
6. Monitor project analytics

### For Students
1. Register/Login as student
2. Join project servers using codes
3. Form or join teams
4. Submit task assignments
5. Collaborate with team members
6. Track progress and deadlines

## 🔧 Configuration

### Backend Configuration
- Database connection in `backend/config/postgres.js`
- JWT settings in `backend/config/jwt.js`
- Cloudinary setup in `backend/config/cloudinary.js`

### Frontend Configuration
- API base URL in `frontend/src/services/api.js`
- Socket.io connection in `frontend/src/services/socket.js`

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For support, please open an issue in the GitHub repository.

---

**Deployed on Vercel**: [Your Vercel URL will appear here after deployment]