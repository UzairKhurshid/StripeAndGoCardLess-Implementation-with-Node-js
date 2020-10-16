const auth=(req,res,next)=>{ 
    let token=req.jwtToken
    const mySecretKey="secretKeyToHashJWT"
    //let token=""
    if (!token) {
        //return res.status(403).send({ message: "No token provided!" });
        console.log('Authentication Failed . Token not found')
        return res.redirect('/')
      }
    jwt.verify(token, mySecretKey, (err, decoded) => {
        if (err) {
          //return res.status(401).send({ message: "Unauthorized!" });
          console.log('Authentication Failed')
          return res.redirect('/')
        }
        req.email = decoded.email;
        req.isLoggedIn=decoded.isLoggedIn
        next();
      });

    
}

module.exports=auth