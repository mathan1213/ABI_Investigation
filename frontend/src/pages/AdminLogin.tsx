import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export const AdminLogin: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    // Admins log in through the normal sign-in page and are redirected to /admin
    navigate('/login', { replace: true });
  }, [navigate]);

  return null;
};

export default AdminLogin;
