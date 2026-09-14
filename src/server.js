require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const { query, initDb } = require("./db");
const { requireAuth, requireRole } = require("./auth");

const app = express();
const PORT = Number(process.env.PORT || 8080);
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);

app.use(helmet());

app.use(cors({
  origin: process.env.CORS_ORIGIN === "*"
    ? true
    : process.env.CORS_ORIGIN,
  credentials: false
}));

app.use(express.json({ limit: "2mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api/", limiter);

const storageRoot = path.join(process.cwd(), "storage");
const audioDir = path.join(storageRoot, "audio");
const coverDir = path.join(storageRoot, "covers");
const videoDir = path.join(storageRoot, "videos");

for (const dir of [audioDir, coverDir, videoDir]) {
  fs.mkdirSync(dir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(
        null,
        file.mimetype.startsWith("audio/")
          ? audioDir
          : coverDir
      );
    },

    filename: (req, file, cb) => {
      cb(
        null,
        `${uuid()}${path.extname(file.originalname).toLowerCase()}`
      );
    }
  }),

  limits: {
    fileSize: 500 * 1024 * 1024
  }
});


/* HEALTH */

app.get("/api/health", async (req, res, next) => {
  try {
    await query("SELECT 1");

    res.json({
      ok: true,
      service: "AVESON Backend",
      version: "1.0.0"
    });
  } catch (e) {
    next(e);
  }
});


/* ARTIST REGISTER */

app.post("/api/register", async (req, res, next) => {
  try {
    const { email, password, displayName } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const normalized = String(email)
      .trim()
      .toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
      return res.status(400).json({
        error: "Invalid email"
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const exists = await query(
      "SELECT id FROM users WHERE email=$1",
      [normalized]
    );

    if (exists.rowCount) {
      return res.status(409).json({
        error: "Account already exists"
      });
    }

    const id = uuid();

    const hash = await bcrypt.hash(
      password,
      12
    );

    await query(
      `INSERT INTO users
       (id,email,password_hash,role,display_name)
       VALUES($1,$2,$3,'artist',$4)`,
      [
        id,
        normalized,
        hash,
        String(displayName || "Artist").trim() || "Artist"
      ]
    );

    res.status(201).json({
      ok: true,
      message: "Artist account created"
    });

  } catch (e) {
    next(e);
  }
});


/* ADMIN BOOTSTRAP */

app.post("/api/admin/bootstrap", async (req, res, next) => {
  try {
    const bootstrapKey =
      process.env.ADMIN_BOOTSTRAP_KEY;

    if (
      !bootstrapKey ||
      req.headers["x-bootstrap-key"] !== bootstrapKey
    ) {
      return res.status(403).json({
        error: "Bootstrap disabled or invalid key"
      });
    }

    const {
      email,
      password,
      displayName
    } = req.body;

    if (
      !email ||
      !password ||
      String(password).length < 10
    ) {
      return res.status(400).json({
        error:
          "Admin email and a 10+ character password are required"
      });
    }

    const normalized = String(email)
      .trim()
      .toLowerCase();

    const hash = await bcrypt.hash(
      password,
      12
    );

    const id = uuid();

    await query(`
      INSERT INTO users
      (id,email,password_hash,role,display_name)
      VALUES($1,$2,$3,'admin',$4)

      ON CONFLICT(email)
      DO UPDATE SET
        password_hash=EXCLUDED.password_hash,
        role='admin',
        display_name=EXCLUDED.display_name
    `, [
      id,
      normalized,
      hash,
      String(displayName || "AVESON Admin")
    ]);

    res.json({
      ok: true,
      message: "Admin account ready"
    });

  } catch (e) {
    next(e);
  }
});


/* LOGIN */

app.post("/api/login", async (req, res, next) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalized = String(email || "")
      .trim()
      .toLowerCase();

    const result = await query(
      "SELECT * FROM users WHERE email=$1",
      [normalized]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(
        String(password || ""),
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const token = uuid();

    const expires = new Date(
      Date.now() +
      SESSION_DAYS * 86400000
    );

    await query(
      `INSERT INTO sessions
       (id,user_id,expires_at)
       VALUES($1,$2,$3)`,
      [
        token,
        user.id,
        expires
      ]
    );

    res.json({
      token,
      expiresAt: expires.toISOString(),

      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        displayName: user.display_name
      }
    });

  } catch (e) {
    next(e);
  }
});


/* LOGOUT */

app.post(
  "/api/logout",
  requireAuth,
  async (req, res, next) => {

    try {

      const token =
        req.headers.authorization?.slice(7) ||
        req.headers["x-aveson-session"];

      await query(
        "DELETE FROM sessions WHERE id=$1",
        [token]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      next(e);
    }
  }
);


/* CURRENT USER */

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {

    res.json({
      user: req.user
    });

  }
);


/* RELEASE LIST */

app.get(
  "/api/releases",
  requireAuth,
  async (req, res, next) => {

    try {

      const params = [];

      let sql = `
        SELECT
          r.*,
          u.email AS artist_email,
          u.display_name AS account_name

        FROM releases r

        JOIN users u
        ON u.id = r.artist_id
      `;

      if (req.user.role === "artist") {

        params.push(req.user.id);

        sql +=
          " WHERE r.artist_id=$1";
      }

      sql +=
        " ORDER BY r.created_at DESC";

      const result =
        await query(sql, params);

      res.json({
        releases: result.rows
      });

    } catch (e) {
      next(e);
    }
  }
);


/* RELEASE UPLOAD */

app.post(
  "/api/releases",
  requireAuth,
  requireRole("artist"),

  upload.fields([
    {
      name: "audio",
      maxCount: 1
    },
    {
      name: "cover",
      maxCount: 1
    }
  ]),

  async (req, res, next) => {

    try {

      const b = req.body;

      if (!b.title) {
        return res.status(400).json({
          error: "Release title is required"
        });
      }

      if (!req.files?.audio?.[0]) {
        return res.status(400).json({
          error: "Audio file is required"
        });
      }

      if (!req.files?.cover?.[0]) {
        return res.status(400).json({
          error: "Cover file is required"
        });
      }

      const id = uuid();

      const audio =
        req.files.audio[0];

      const cover =
        req.files.cover[0];

      await query(`
        INSERT INTO releases(

          id,
          artist_id,
          title,
          type,
          artist_name,
          featuring,
          genre,
          language,
          release_date,
          label,
          copyright_owner,
          lyrics,
          explicit,
          audio_original_name,
          audio_path,
          cover_original_name,
          cover_path,
          status

        )

        VALUES(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,
          $10,$11,$12,$13,$14,$15,$16,$17,
          'PENDING_REVIEW'
        )
      `, [

        id,
        req.user.id,

        b.title,
        b.type || "Single",

        b.artistName ||
        req.user.display_name,

        b.featuring || null,
        b.genre || null,
        b.language || null,

        b.releaseDate || null,

        b.label || null,

        b.copyrightOwner ||
        null,

        b.lyrics || null,

        String(b.explicit) === "true",

        audio.originalname,
        audio.path,

        cover.originalname,
        cover.path

      ]);

      res.status(201).json({

        ok: true,

        releaseId: id,

        status: "PENDING_REVIEW"

      });

    } catch (e) {
      next(e);
    }
  }
);


/* SINGLE RELEASE */

app.get(
  "/api/releases/:id",
  requireAuth,
  async (req, res, next) => {

    try {

      const result =
        await query(`

          SELECT
            r.*,
            u.email AS artist_email,
            u.display_name AS account_name

          FROM releases r

          JOIN users u
          ON u.id = r.artist_id

          WHERE r.id=$1

        `, [req.params.id]);

      const release =
        result.rows[0];

      if (!release) {
        return res.status(404).json({
          error: "Release not found"
        });
      }

      if (
        req.user.role === "artist" &&
        release.artist_id !== req.user.id
      ) {
        return res.status(403).json({
          error: "Forbidden"
        });
      }

      res.json({
        release
      });

    } catch (e) {
      next(e);
    }
  }
);


/* ADMIN REVIEW */

app.patch(
  "/api/releases/:id/review",
  requireAuth,
  requireRole("admin"),

  async (req, res, next) => {

    try {

      const {
        status,
        note
      } = req.body;

      const allowed = [
        "CHANGES_REQUIRED",
        "APPROVED",
        "REJECTED",
        "RELEASED"
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          error: "Invalid review status"
        });
      }

      const result =
        await query(`

          UPDATE releases

          SET
            status=$1,
            review_note=$2,
            reviewed_by=$3,
            reviewed_at=NOW(),
            updated_at=NOW()

          WHERE id=$4

          RETURNING *

        `, [
          status,
          note || null,
          req.user.id,
          req.params.id
        ]);

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Release not found"
        });
      }

      res.json({
        ok: true,
        release: result.rows[0]
      });

    } catch (e) {
      next(e);
    }
  }
);


/* ARTISTS */

app.get(
  "/api/artists",
  requireAuth,
  requireRole("admin"),

  async (req, res, next) => {

    try {

      const result =
        await query(`

          SELECT
            u.id,
            u.email,
            u.display_name,
            u.created_at,
            COUNT(r.id)::int AS release_count

          FROM users u

          LEFT JOIN releases r
          ON r.artist_id = u.id

          WHERE u.role='artist'

          GROUP BY u.id

          ORDER BY u.created_at DESC

        `);

      res.json({
        artists: result.rows
      });

    } catch (e) {
      next(e);
    }
  }
);


/* ADMIN QUEUE */

app.get(
  "/api/admin/queue",
  requireAuth,
  requireRole("admin"),

  async (req, res, next) => {

    try {

      const result =
        await query(`

          SELECT
            r.*,
            u.email AS artist_email,
            u.display_name AS account_name

          FROM releases r

          JOIN users u
          ON u.id = r.artist_id

          WHERE r.status='PENDING_REVIEW'

          ORDER BY r.created_at ASC

        `);

      res.json({
        queue: result.rows
      });

    } catch (e) {
      next(e);
    }
  }
);


/* STORAGE */

app.use(
  "/storage",
  express.static(storageRoot, {
    fallthrough: false,

    setHeaders: res =>
      res.setHeader(
        "Cache-Control",
        "private, max-age=3600"
      )
  })
);


/* ERROR HANDLER */

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(500).json({
      error: "Internal server error"
    });

  }
);


/* START */

initDb()

  .then(() => {

    app.listen(
      PORT,
      () => {
        console.log(
          `AVESON Backend listening on :${PORT}`
        );
      }
    );

  })

  .catch(err => {

    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);

  });