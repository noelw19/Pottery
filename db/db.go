package db

import (
	"database/sql"
	"fmt"
	"log"
	"reflect"

	_ "github.com/mattn/go-sqlite3"
)

type Db struct {
	Filename string
}

type ip_data struct {
	Ip           string `field:"ip"`
	Country      string `field:"country"`
	Country_code string `field:"country_code"`
	City         string `field:"city"`
	Region       string `field:"region"`
	ISP          string `field:"isp"`
	Hits         string `field:"hits"`
}

type Endpoint_hit struct {
	Id         int    `json:"id"`
	Ip         string `json:"ip"`
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	Headers    string `json:"headers"`
	User_agent string `json:"user_agent"`
	Timestamp  string `json:"timestamp"`
	Honeypot   string `json:"honeypot"`
	Req_body   string `json:"req_body"`
}

type blacklist struct {
	Ip string `json:"ip"`
}

// create db to store ips and counts endpoints visited, geolocations

func (mod *Db) Start() {
	mod.Filename = "./honeypot.db"

	err := mod.BaseExecRunner(mod.create_queries().CREATE.Table_user)
	if err != nil {
		fmt.Println("Error executing query in Start():", err, mod.create_queries().CREATE.Table_user)
	}

	err = mod.BaseExecRunner(mod.create_queries().CREATE.Table_endpoint_hit)
	if err != nil {
		fmt.Println("Error executing query in Start():", err, mod.create_queries().CREATE.Table_endpoint_hit)
	}

	err = mod.BaseExecRunner(mod.create_queries().CREATE.Table_blacklist)
	log.Println("create tbl: ", err)
	if err != nil {
		fmt.Println("Error executing query in Start():", err, mod.create_queries().CREATE.Table_blacklist)
	}

	// mod.Set_Blacklist()

	fmt.Println("")
	fmt.Println("Pottery Database initialized")
	fmt.Println("")
}

type SQL_Query struct {
	Query string
}

func (mod *Db) BaseExecRunner(query string) error {
	db, err := sql.Open("sqlite3", mod.Filename)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func (mod *Db) Base_IP_Data_QueryRunner(query string) (*[]ip_data, error) {
	db, err := sql.Open("sqlite3", mod.Filename)
	if err != nil {
		return &[]ip_data{}, err
	}
	defer db.Close()
	rows, err := db.Query(query)
	if err != nil {
		return &[]ip_data{}, err
	}

	ipdata := mod.ip_data_parse(rows)
	return ipdata, nil
}

func (db *Db) CheckIP_blacklist(ip string) bool {
	inBlacklist := false
	data, err := db.Base_blacklist_QueryRunner(`select ip from blacklist`)
	if err != nil {
		log.Println("error getting blacklist from DB: ", err)
	}
	for _, bl := range *data {
		if bl.Ip == ip {
			inBlacklist = true
		}
	}
	return inBlacklist
}

func (mod *Db) Base_blacklist_QueryRunner(query string) (*[]blacklist, error) {
	db, err := sql.Open("sqlite3", mod.Filename)
	if err != nil {
		return &[]blacklist{}, err
	}
	defer db.Close()
	rows, err := db.Query(query)
	if err != nil {
		return &[]blacklist{}, err
	}

	endpointData := mod.blacklist_parse(rows)
	return endpointData, nil
}

func (mod *Db) Base_Endpoint_Hit_QueryRunner(query string) (*[]Endpoint_hit, error) {
	db, err := sql.Open("sqlite3", mod.Filename)
	if err != nil {
		return &[]Endpoint_hit{}, err
	}
	defer db.Close()
	rows, err := db.Query(query)
	if err != nil {
		return &[]Endpoint_hit{}, err
	}

	endpointData := mod.endpoint_hit_parse(rows)
	return endpointData, nil
}

func (mod *Db) blacklist_parse(rows *sql.Rows) *[]blacklist {
	ipdata := &[]blacklist{}
	for rows.Next() {
		data := blacklist{}
		s := reflect.ValueOf(&data).Elem()
		numCols := s.NumField()
		columns := make([]any, numCols)
		for i := range numCols {
			field := s.Field(i)
			columns[i] = field.Addr().Interface()
		}

		err := rows.Scan(columns...)
		if err != nil {
			log.Fatal(err)
		}
		*ipdata = append(*ipdata, data)
	}
	return ipdata
}

func (mod *Db) ip_data_parse(rows *sql.Rows) *[]ip_data {
	ipdata := &[]ip_data{}
	for rows.Next() {
		data := ip_data{}
		s := reflect.ValueOf(&data).Elem()
		numCols := s.NumField()
		columns := make([]interface{}, numCols)
		for i := range numCols {
			field := s.Field(i)
			columns[i] = field.Addr().Interface()
		}

		err := rows.Scan(columns...)
		if err != nil {
			log.Fatal(err)
		}
		*ipdata = append(*ipdata, data)
	}
	return ipdata
}

func (mod *Db) endpoint_hit_parse(rows *sql.Rows) *[]Endpoint_hit {
	ipdata := &[]Endpoint_hit{}
	for rows.Next() {
		data := Endpoint_hit{}
		s := reflect.ValueOf(&data).Elem()
		numCols := s.NumField()
		columns := make([]any, numCols)
		for i := range numCols {
			field := s.Field(i)
			columns[i] = field.Addr().Interface()
		}

		err := rows.Scan(columns...)
		if err != nil {
			log.Fatal(err)
		}
		*ipdata = append(*ipdata, data)
	}
	return ipdata
}

func (mod *Db) Update_IP_Hit(ip string) error {
	query := fmt.Sprintf(`
		UPDATE ip_data
		SET hits = hits + 1
		WHERE ip = "%s"`, ip)
	err := mod.BaseExecRunner(query)
	if err != nil {
		return err
	}
	return nil
}
func (mod *Db) Get_IP_DATA_All() *[]ip_data {
	query := "select * from ip_data"
	data, err := mod.Base_IP_Data_QueryRunner(query)
	if err != nil {
		log.Println("Error getting ip_data all from db")
		return nil
	}
	return data
}

func (mod *Db) Get_Endpoint_Hit_All() *[]Endpoint_hit {
	res, err := mod.Base_Endpoint_Hit_QueryRunner("select * from endpoint_hit")
	if err != nil {
		log.Println("error getting endpoint_hit all data from DB: ", err)
		return nil
	}
	return res
}

func (mod *Db) Get_IP_From_DB(ip string) *[]ip_data {
	query := fmt.Sprintf(`select * from ip_data where ip = "%s"`, ip)
	result, err := mod.Base_IP_Data_QueryRunner(query)
	if err != nil {
		log.Println("Error getting ip_data from db")
		return &[]ip_data{}
	}
	return result

}

func (mod *Db) Set_Blacklist(IP string) error {
	query := fmt.Sprintf(`
	INSERT INTO blacklist (ip)
	VALUES("%s");`, IP)
	err := mod.BaseExecRunner(query)
	if err != nil {
		log.Println("Error updating db: ", err)
	}
	return nil
}

func (mod *Db) Set_IP_DATA(IP string, Country string, CountryCode string, City string, Region string, ISP string) error {
	query := fmt.Sprintf(`
	INSERT INTO ip_data (ip, country, country_code, city, region, isp)
	VALUES("%s", "%s", "%s", "%s", "%s", "%s");
`, IP, Country, CountryCode, City, Region, ISP)
	err := mod.BaseExecRunner(query)
	if err != nil {
		log.Println("Error updating db: ", err)
	}
	return nil
}

func (mod *Db) Set_Endpoint_Hit(IP string, Endpoint string, Method string, Headers string, User_Agent string, HoneyPot string, Req_Body string) error {
	query := fmt.Sprintf(`
	INSERT INTO endpoint_hit (ip, endpoint, method, headers, user_agent, honeypot, req_body)
	VALUES("%s", "%s", "%s", "%s", "%s", "%s", '%s');
`, IP, Endpoint, Method, Headers, User_Agent, HoneyPot, Req_Body)
	err := mod.BaseExecRunner(query)
	if err != nil {
		log.Println("Error updating db: ", err)
	}
	return nil
}
