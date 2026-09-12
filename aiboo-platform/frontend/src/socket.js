// frontend/src/socket.js
import io from 'socket.io-client';

const SOCKET_URL = 'http://localhost:4000'; // Your backend port

let socket;

export const connectSocket = () => {
    if (!socket) {
        socket = io(SOCKET_URL, {
            transports: ['websocket'],
            autoConnect: true,
            withCredentials: true,
        });
        console.log('🔌 Connecting to backend socket at', SOCKET_URL);
    }
    return socket;
};

export const getSocket = () => {
    if (!socket) {
        throw new Error('Socket not connected. Call connectSocket() first.');
    }
    return socket;
};

export const disconnectSocket = () => {
    if (socket) {
        socket.disconnect();
        socket = null;
        console.log('🔌 Disconnected from backend socket');
    }
};