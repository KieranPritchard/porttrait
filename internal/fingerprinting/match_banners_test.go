package fingerprinting

import (
	"reflect"
	"sort"
	"testing"
)

var testDatabaseFiles = []string{
	"dns_versionbind.xml",
	"ftp_banners.xml",
	"hp_pjl_id.xml",
	"html_title.xml",
	"http_cookies.xml",
	"http_servers.xml",
	"http_wwwauth.xml",
	"http_xpoweredby.xml",
	"imap_banners.xml",
	"mysql_banners.xml",
	"nntp_banners.xml",
	"ntp_banners.xml",
	"pop_banners.xml",
	"sip_banners.xml",
	"smtp_banners.xml",
	"snmp_sysdescr.xml",
	"ssh_banners.xml",
	"telnet_banners.xml",
	"x11_banners.xml",
}

func TestSelectTargetsCoversEmbeddedDatabases(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		wantDBs []string
	}{
		{
			name:   "HTTP headers and title with X-Powered-By",
			banner: "HTTP/1.1 401 Unauthorized\r\nServer: Transmission\r\nWWW-Authenticate: Basic realm=\"Transmission\"\r\nSet-Cookie: PHPSESSID=deleted\r\nX-Powered-By: PHP/8.2.14\r\n\r\n<title>FRITZ!Box</title>",
			wantDBs: []string{
				"html_title.xml",
				"http_cookies.xml",
				"http_servers.xml",
				"http_wwwauth.xml",
				"http_xpoweredby.xml",
			},
		},
		{name: "SSH", banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", wantDBs: []string{"ssh_banners.xml"}},
		{name: "FTP and SMTP", banner: "220 Microsoft FTP Service", wantDBs: []string{"ftp_banners.xml", "smtp_banners.xml"}},
		{name: "POP3", banner: "+OK Dovecot ready.", wantDBs: []string{"pop_banners.xml"}},
		{name: "IMAP", banner: "* OK Dovecot ready.", wantDBs: []string{"imap_banners.xml"}},
		{name: "NNTP 200", banner: "200 NNTP Service ready - posting allowed", wantDBs: []string{"nntp_banners.xml"}},
		{name: "NNTP 201", banner: "201 NNTP Service ready - no posting", wantDBs: []string{"nntp_banners.xml"}},
		{name: "SIP response", banner: "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.5.0\r\n\r\n", wantDBs: []string{"sip_banners.xml"}},
		{name: "PJL response", banner: "@PJL INFO ID\r\nHP LaserJet 4250", wantDBs: []string{"hp_pjl_id.xml"}},
		{name: "MySQL greeting", banner: "5.7.42-log", wantDBs: []string{"mysql_banners.xml"}},
		{name: "Telnet", banner: "User:", wantDBs: []string{"telnet_banners.xml"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets := SelectTargets(test.banner, testDatabaseFiles)
			gotDBs := make([]string, 0, len(targets))
			for _, target := range targets {
				if len(gotDBs) == 0 || gotDBs[len(gotDBs)-1] != target.dbFile {
					gotDBs = append(gotDBs, target.dbFile)
				}
			}
			sort.Strings(gotDBs)
			if !reflect.DeepEqual(gotDBs, test.wantDBs) {
				t.Fatalf("selectTargets() databases = %v, want %v", gotDBs, test.wantDBs)
			}
		})
	}
}

func TestSelectTargetsExtractsHTTPFingerprintInputs(t *testing.T) {
	banner := "HTTP/1.1 401 Unauthorized\r\nServer: Transmission\r\nWWW-Authenticate: Basic realm=\"Transmission\"\r\nSet-Cookie: PHPSESSID=deleted\r\nX-Powered-By: PHP/8.2.14\r\n\r\n<title>FRITZ!Box</title>"
	targets := SelectTargets(banner, testDatabaseFiles)
	got := make(map[string]map[string]bool)
	for _, target := range targets {
		if got[target.dbFile] == nil {
			got[target.dbFile] = make(map[string]bool)
		}
		got[target.dbFile][target.input] = true
	}

	for dbFile, input := range map[string]string{
		"http_servers.xml":    "Transmission",
		"http_wwwauth.xml":    `Basic realm="Transmission"`,
		"http_cookies.xml":    "PHPSESSID=deleted",
		"html_title.xml":      "FRITZ!Box",
		"http_xpoweredby.xml": "PHP/8.2.14",
	} {
		if !got[dbFile][input] {
			t.Errorf("selectTargets() missing %q for %s", input, dbFile)
		}
	}
}

func TestMatchBannersMatchesExpandedDatabases(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		want   MatchResult
	}{
		{
			name:   "HTTP WWW-Authenticate header",
			banner: "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Transmission\"\r\n\r\n",
			want:   MatchResult{Vendor: "TransmissionBT", Product: "Transmission"},
		},
		{
			name:   "HTTP X-Powered-By header",
			banner: "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.14\r\n\r\n",
			want:   MatchResult{Vendor: "PHP", Product: "PHP", Version: "8.2.14"},
		},
		{
			name:   "FTP greeting",
			banner: "220 Microsoft FTP Service",
			want:   MatchResult{Vendor: "Microsoft", Product: "IIS"},
		},
		{
			name:   "SMTP greeting",
			banner: "220 Sendmail ESMTP ready",
			want:   MatchResult{Vendor: "Sendmail", Product: "Sendmail"},
		},
		{
			name:   "POP3 greeting",
			banner: "+OK Dovecot ready.",
			want:   MatchResult{Vendor: "Dovecot", Product: "Dovecot"},
		},
		{
			name:   "IMAP greeting",
			banner: "* OK Dovecot ready.",
			want:   MatchResult{Vendor: "Dovecot", Product: "Dovecot"},
		},
		{
			name:   "MySQL greeting",
			banner: "5.7.42-log",
			want:   MatchResult{Vendor: "Oracle", Product: "MySQL", Version: "5.7.42"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := MatchBanners(test.banner)
			if err != nil {
				t.Fatalf("MatchBanners() error = %v", err)
			}
			for _, match := range matches {
				if match == test.want {
					return
				}
			}
			t.Fatalf("MatchBanners() = %v, want a match for %+v", matches, test.want)
		})
	}
}
