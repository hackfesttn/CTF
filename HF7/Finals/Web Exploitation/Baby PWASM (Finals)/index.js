#!/usr/bin/node

module.exports = ((app, http, path) => {
	app.get("/", (req, res) => {
		if (req.socket.remoteAddress === "127.0.0.1")
			res.send("Hackfest{base_fake_flag} ");
		if (req.session.username === "SLIMEN")
			res.redirect("/elbirou");
		res.sendFile(path.join(__dirname, "pages/index.html"));
	});

	app.get("/sidikhouya", (req, res) => {
		let username = req.query.username;
		if (username && (typeof username === "string")) {
			if (!/slimen/i.test(username)) {
				req.session.username = username.toUpperCase();
			}
		}
		res.redirect("/elbirou");
		res.end();
	});

	app.get("/elbirou", (req, res) => {
		if (req.session.username === "SLIMEN") {
			res.sendFile(path.join(__dirname, "/pages/elbirou.html"))
		} else {
			res.redirect("/");
		}
	});

	app.get("/elficha", (req, res) => {
		if (req.session.username === "SLIMEN") {
			let patient = JSON.parse(req.query.patient);
			if (Object.keys(patient).indexOf("fb_uri") === -1) {
				patient = Object.assign({}, patient);
				let fb_uri = patient.fb_uri;
				if (!fb_uri || (typeof fb_uri !== "string"))
					res.sendFile(path.join(__dirname, "/static/imgs/bajbouj.gif"));
				fb_uri = fb_uri.replace(/[\[a-zA-Z0-9:\]]/gm, "");
				try {
					let req = http.get("http://" + fb_uri, resp => {
						resp.on("data", data => res.send(data));
					});
					req.on("error", error => {
						res.sendFile(path.join(__dirname, "/static/imgs/slimen1.gif"));
					});
				} catch (error) {
					console.log(error);
					res.sendFile(path.join(__dirname, "/static/imgs/slimen2.gif"));
				}
			} else {
				res.sendFile(path.join(__dirname, "/static/imgs/bajbouj.gif"));
			}
		} else {
			res.redirect("/");
		}
	});
});
