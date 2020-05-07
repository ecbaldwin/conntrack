package conntrack

import (
	"fmt"
	"net"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
	"github.com/pkg/errors"
)

const (
	opUnSnat = "Snat unmarshal"
	opUnSnatProto = "SnatProto unmarshal"
)

type SnatProto struct {
	MinPort, MaxPort uint16
}

// Snat holds snat informatiot
type Snat struct {
	MinIp, MaxIp net.IP
	Proto SnatProto
}

func (sn Snat) filled() bool {
	return len(sn.MinIp) != 0 && len(sn.MaxIp) != 0 && sn.Proto.filled()
}

// marshal marshals an Snat to a netfilter.Attribute.
func (sn Snat) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaNatSrc), Nested: true, Children: make([]netfilter.Attribute, 1, 2)}

	// MaxIp is completely left out in libconntrack
	if minIp := sn.MinIp.To4(); minIp != nil {
		nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaNatV4Minip), Data: minIp}
	} else {
		nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaNatV6Minip), Data: sn.MinIp.To16()}
	}

	if sn.Proto.filled() {
		nfa.Children = append(nfa.Children, sn.Proto.marshal())
	}

	return nfa
}

// unmarshal unmarshals into an Snat structure
func (sn *Snat) unmarshal(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ctaNatType(ad.Type()) {
		case ctaNatProto:
			var snp SnatProto
			ad.Nested(snp.unmarshal)
			sn.Proto = snp
			continue
		}

		b := ad.Bytes()

		var ip net.IP
		switch ctaNatType(ad.Type()) {
		case ctaNatV4Minip, ctaNatV4Maxip:
			ip = net.IPv4(b[0], b[1], b[2], b[3])
			if len(b) != 4 {
				return errIncorrectSize
			}

		case ctaNatV6Minip, ctaNatV6Maxip:
			ip = net.IP(b)
			if len(b) != 16 {
				return errIncorrectSize
			}

		default:
			return errors.Wrap(fmt.Errorf(errAttributeChild, ad.Type()), opUnSnat)
		}

		switch ctaNatType(ad.Type()) {
		case ctaNatV4Minip, ctaNatV6Minip:
			sn.MinIp = ip

		case ctaNatV4Maxip, ctaNatV6Maxip:
			sn.MaxIp = ip
		}
	}

	return ad.Err()
}

func (snp SnatProto) filled() bool {
	return snp.MinPort != 0 && snp.MaxPort != 0
}

// marshal marshals an SnatProto to a netfilter.Attribute.
func (snp SnatProto) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaNatProto), Nested: true, Children: make([]netfilter.Attribute, 2, 2)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaProtonatPortMin), Data: netfilter.Uint16Bytes(snp.MinPort)}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaProtonatPortMax), Data: netfilter.Uint16Bytes(snp.MaxPort)}

	return nfa
}

// unmarshal unmarshals into an SnatProto structure
func (snp *SnatProto) unmarshal(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ctaNatProtoType(ad.Type()) {
		case ctaProtonatPortMin:
			snp.MinPort = ad.Uint16()

		case ctaProtonatPortMax:
			snp.MaxPort = ad.Uint16()

		default:
			return errors.Wrap(fmt.Errorf(errAttributeChild, ad.Type()), opUnSnat)
		}
	}

	return ad.Err()
}
