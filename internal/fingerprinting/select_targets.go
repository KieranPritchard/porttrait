package fingerprinting

import (
	"html"
	"sort"
	"strings"
)

// Works out which embedded databases and banner fragments apply to the response.
func SelectTargets(banner string, dbFiles []string) []matchTarget {
	// Trim whitespace from the banner and return nil if it's empty
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return nil
	}

	// Map to hold database files and their corresponding banner fragments
	inputs := make(map[string][]string)
	firstLine := strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])

	// Determine the type of banner based on its first line and extract relevant inputs for matching
	switch {
	// HTTP responses — extract the Server header for http_servers.xml
	case strings.HasPrefix(strings.ToUpper(firstLine), "HTTP/"):
		addMatchInput(inputs, "http_servers.xml", extractServerHeader(banner))
		for _, value := range httpHeaderValues(banner, "WWW-Authenticate") {
			addMatchInput(inputs, "http_wwwauth.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "Set-Cookie") {
			addMatchInput(inputs, "http_cookies.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "X-Powered-By") {
			addMatchInput(inputs, "http_xpoweredby.xml", value)
		}
		addMatchInput(inputs, "html_title.xml", httpStatusText(firstLine))
		if title := htmlTitlePattern.FindStringSubmatch(httpBody(banner)); len(title) == 2 {
			addMatchInput(inputs, "html_title.xml", html.UnescapeString(title[1]))
		}
	// SSH banners — extract the version string for ssh_banners.xml
	case strings.HasPrefix(firstLine, "SSH-"):
		parts := strings.SplitN(firstLine, "-", 3)
		if len(parts) == 3 {
			addMatchInput(inputs, "ssh_banners.xml", parts[2])
		}
	// FTP and SMTP both greet with 220; the Recog patterns expect the text after it.
	case strings.HasPrefix(firstLine, "220"):
		// FTP and SMTP both greet with 220; the Recog patterns expect the text after it.
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if len(line) >= 4 && line[:3] == "220" && (line[3] == ' ' || line[3] == '-') {
				addMatchInput(inputs, "ftp_banners.xml", line)
				addMatchInput(inputs, "smtp_banners.xml", line)
				addMatchInput(inputs, "ftp_banners.xml", line[4:])
				addMatchInput(inputs, "smtp_banners.xml", line[4:])
			}
		}
	// POP3 and IMAP both greet with +OK or * OK; the Recog patterns expect the text after it.
	case strings.HasPrefix(firstLine, "+OK") || strings.HasPrefix(firstLine, "-ERR"):
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+OK") || strings.HasPrefix(line, "-ERR") {
				addMatchInput(inputs, "pop_banners.xml", strings.TrimSpace(line[3:]))
			}
		}
	// IMAP can also greet with * OK or * PREAUTH, which is handled in the next case.
	case strings.HasPrefix(firstLine, "* OK") || strings.HasPrefix(firstLine, "* PREAUTH"):
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "* OK"):
				addMatchInput(inputs, "imap_banners.xml", strings.TrimSpace(line[len("* OK"):]))
			case strings.HasPrefix(line, "* PREAUTH"):
				addMatchInput(inputs, "imap_banners.xml", strings.TrimSpace(line[len("* PREAUTH"):]))
			}
		}
	// NNTP servers greet with 200 (posting allowed) or 201 (no posting).
	case strings.HasPrefix(firstLine, "200") || strings.HasPrefix(firstLine, "201"):
		// NNTP servers greet with 200 (posting allowed) or 201 (no posting).
		// Try both NNTP-specific and the generic SMTP/FTP databases because 200/201
		// can occasionally appear in other protocols.
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			code := ""
			if len(line) >= 4 && (line[:3] == "200" || line[:3] == "201") && (line[3] == ' ' || line[3] == '-') {
				code = line[:3]
			}
			if code != "" {
				addMatchInput(inputs, "nntp_banners.xml", line)
				addMatchInput(inputs, "nntp_banners.xml", line[4:])
			}
		}
	// SIP responses — extract the Server header for sip_banners.xml
	case strings.HasPrefix(strings.ToUpper(firstLine), "SIP/"):
		// SIP responses — extract the Server header for sip_banners.xml
		for _, value := range httpHeaderValues(banner, "Server") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "User-Agent") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}

	// PJL responses start with @PJL and contain the printer model in the INFO ID response.
	case strings.HasPrefix(strings.ToUpper(firstLine), "@PJL"):
		// HP PJL (Printer Job Language) responses
		addMatchInput(inputs, "hp_pjl_id.xml", banner)
		addMatchInput(inputs, "hp_pjl_id.xml", firstLine)

	case isMySQLGreeting(banner):
		// MySQL sends a greeting packet whose version string starts at byte 5.
		// The version is null-terminated ASCII — extract and match it.
		if ver := extractMySQLVersion(banner); ver != "" {
			addMatchInput(inputs, "mysql_banners.xml", ver)
		}

	default:
		addMatchInput(inputs, "telnet_banners.xml", banner)
	}

	// Use sorted database names so match ordering remains stable if files are added.
	names := append([]string(nil), dbFiles...)
	sort.Strings(names)

	var targets []matchTarget
	for _, name := range names {
		for _, input := range inputs[name] {
			targets = append(targets, matchTarget{dbFile: name, input: input})
		}
	}
	return targets
}