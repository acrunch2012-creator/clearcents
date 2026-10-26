
export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        app: "ClearCents",
        status: "online"
      });
    }

    return Response.json({
      app: "ClearCents API",
      message: "API is running"
    });
  }
};
