package view

import "github.com/projectdiscovery/cvemap/pkg/constant"

func loadCustomViewers() MetaViewers {
	m := make(MetaViewers, 5)
	coreViewers(m)
	return m
}

func coreViewers(vv MetaViewers) {
	vv[constant.LowercaseCvemap] = MetaViewer{
		viewerFn: NewCvemap,
	}
}
