import express from "express";
import cors from "cors";
import pkg from "pg";
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Railway te da esta variable
  ssl: { rejectUnauthorized: false }
});

app.get("/usuarios", async (req, res) => {
  const result = await pool.query("SELECT * FROM usuarios");
  res.json(result.rows);
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor corriendo");
});
