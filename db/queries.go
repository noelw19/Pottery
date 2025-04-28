package db

// "github.com/noelw19/honeypot/lib"

type Create struct {
	Table_user         string
	Table_endpoint_hit string
	Table_blacklist    string
}

type Insert struct {
	Table_ip_data      func()
	Table_endpoint_hit string
}

type Queries struct {
	CREATE Create
	INSERT Insert
}

// var gg lib.GeoData
// IP_Data table
// IP | Hit Points |

func (mod *Db) create_queries() Queries {
	return Queries{
		Create{
			Table_user: `
				CREATE TABLE IF NOT EXISTS ip_data (
					ip TEXT NOT NULL PRIMARY KEY,
					country TEXT NOT NULL,
					country_code TEXT NOT NULL,
					city TEXT NOT NULL,
					region TEXT NOT NULL,
					isp TEXT NOT NULL,
					hits INTEGER DEFAULT 1
				);`,
			Table_endpoint_hit: `CREATE TABLE IF NOT EXISTS endpoint_hit (
					id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
					ip TEXT NOT NULL,
					endpoint TEXT,
					method TEXT,
					headers TEXT,
					user_agent TEXT,
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
					honeypot TEXT,
					req_body TEXT,
					CONSTRAINT fk_ip
						FOREIGN KEY (ip)
						REFERENCES ip_data(ip)
					
				);`,
			Table_blacklist: `CREATE TABLE IF NOT EXISTS blacklist (
					id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
					ip TEXT NOT NULL UNIQUE,
					CONSTRAINT fk_ip1
						FOREIGN KEY (ip)
						REFERENCES ip_data(ip)
				);`,
		},
		Insert{},
	}
}
