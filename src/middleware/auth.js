import jwt from "jsonwebtoken";

const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).send("Acesso negado");

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send("Token inválido");
        req.user = user;
        next();
    });
};

export default authenticateToken;