//socket.io chat
const users = {};

io.on("connection", socket => {
  socket.on("new-user", name => {
    users[socket.id] = name;
    //socket.broadcast.emit("user-connected", name);
    socket.broadcast.emit("user-connected", name);
  });
  socket.on("send-chat-message", message => {
    socket.broadcast.emit("chat-message", {
      message: message,
      name: users[socket.id],
    });
  });
  socket.on("disconnect", () => {
    socket.broadcast.emit("user-disconnected", users[socket.id]);
    delete users[socket.id];
  });

  //videocall

  /*socket.on("new-user", name => {
    //socket.broadcast.emit("user-connected", name);
    socket.broadcast.emit("user-connected", name);
  });

  socket.on("disconnect", () => {
    socket.broadcast.emit("user-disconnected", users[socket.id]);
    delete users[socket.id];
  });

  socket.on("join-room", (roomId, userId) => {
    socket.join(roomId);
    socket.broadcast.emit("user-connected", userId);
    //socket.broadcast.emit("user-connected", userId);
    console.log("Your rommId is " + roomId);

    socket.on("message", message => {
      socket.emit("createMessage", message);
    });
  });*/

  socket.on("join-room", (roomId, userId) => {
    socket.join(roomId);
    socket.broadcast.emit("user-connected", userId);
    //socket.broadcast.emit("user-connected", userId);
    console.log("Your rommId is " + roomId);
  });
  socket.on("disconnect", () => {
    socket.broadcast.emit("user-disconnected", users[socket.id]);
    delete users[socket.id];
  });
  socket.on("message", message => {
    socket.broadcast.emit("sendMessage", message);
  });
});
