package wafenginecore

import (
	"SamWaf/common/domaintool"
	"SamWaf/utils"
	"strings"
)

type requestHostMatch struct {
	Host, Port, Code, Kind string
	Found                  bool
	CatchAllLog            string
	Steps                  []string
}

// resolveRequestHost 与请求入口共用同一份路由顺序。
func resolveRequestHost(rt *routingTable, authority string, secure, trace bool) requestHostMatch {
	m := requestHostMatch{Host: authority, Kind: "unmatched"}
	if !strings.Contains(m.Host, ":") {
		if secure {
			m.Host += ":443"
		} else {
			m.Host += ":80"
		}
	}
	if strings.Contains(m.Host, ":") {
		parts := strings.Split(m.Host, ":")
		if len(parts) == 2 {
			m.Port = parts[1]
		}
	}
	if trace {
		m.Steps = append(m.Steps, "authority="+m.Host)
	}
	loose := false
	if targetHost, ok := rt.HostTargetNoPort[utils.GetPureDomain(m.Host)]; ok {
		m.Host = targetHost
		loose = true
		if trace {
			m.Steps = append(m.Steps, "no_port="+targetHost)
		}
	}
	target, ok := rt.HostTarget[m.Host]
	if !ok {
		target, ok = rt.HostTarget[domaintool.MaskSubdomain(m.Host)]
		if ok {
			m.Found, m.Code, m.Kind = true, target.Host.Code, "wildcard"
		}
	} else {
		m.Found, m.Code, m.Kind = true, target.Host.Code, "exact"
		if loose {
			m.Kind = "no_port"
		}
	}
	if !m.Found {
		m.Code, ok = rt.HostTargetMoreDomain[m.Host]
		if ok {
			m.Found, m.Kind = true, "alias"
		} else {
			m.Code, ok = rt.HostTargetMoreDomain[domaintool.MaskSubdomain(m.Host)]
			if ok {
				m.Found, m.Kind = true, "alias_wildcard"
			}
		}
	}
	if trace && m.Found {
		m.Steps = append(m.Steps, m.Kind+"="+m.Code)
	}
	if targetHost, ok := rt.HostTargetNoPort["*"]; ok {
		m.Host = targetHost
		target, ok = rt.HostTarget[m.Host]
		if ok {
			m.Found, m.Code, m.Kind = true, target.Host.Code, "catch_all_no_port"
			m.CatchAllLog = "触发*逻辑和来源port"
			if trace {
				m.Steps = append(m.Steps, m.Kind+"="+m.Code)
			}
		}
	} else {
		target, ok = rt.HostTarget["*:"+m.Port]
		if ok {
			m.Found, m.Code, m.Kind = true, target.Host.Code, "catch_all"
			m.CatchAllLog = "触发*逻辑"
			if trace {
				m.Steps = append(m.Steps, m.Kind+"="+m.Code)
			}
		}
	}
	if trace && !m.Found {
		m.Steps = append(m.Steps, "unmatched")
	}
	return m
}
