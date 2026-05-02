import express from "express";
import type { NextFunction, Request, Response } from "express";

export function setupRequestLogging(app: express.Application) {
  app.use((req, res, next) => {
    const start = Date.now();
    const path = req.path;

    res.on("finish", () => {
      if (!path.startsWith("/api")) return;

      const duration = Date.now() - start;
      console.log(`${req.method} ${path} ${res.statusCode} in ${duration}ms`);
    });

    next();
  });
}

export function setupErrorHandler(app: express.Application) {
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    const error = err as {
      status?: number;
      statusCode?: number;
      type?: string;
      message?: string;
    };

    const status = error.status || error.statusCode || 500;

    if (res.headersSent) {
      return next(err);
    }

    // Body-parser errors. These are client mistakes (oversize payload,
    // syntactically invalid JSON) - surface them with the SAME
    // { error: ... } shape every API route uses, not the generic
    // Internal-Server-Error shape, and don't pollute the server log with
    // "Internal Server Error" for what is really just a malformed request.
    if (status === 413) {
      return res.status(413).json({ error: "Payload too large" });
    }
    if (status === 400 && error.type === "entity.parse.failed") {
      return res.status(400).json({ error: "Invalid JSON" });
    }

    console.error("Internal Server Error");
    return res.status(status).json({ error: "Internal server error" });
  });
}
