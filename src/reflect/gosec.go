package reflect

import (
	r "runtime"
	u "unsafe"
)

func ConvTypePtr(tpe *r.DPTpe) Type {
	rtpe := (*rtype)(u.Pointer(tpe))
	return PtrTo(rtpe)
}

func ConvTypeToDPTpe(tpe Type) *r.DPTpe {
	ptr := ValueOf(tpe).Pointer()
	return (*r.DPTpe)(u.Pointer(ptr))
}

func ConvDPTpeToType(tpe *r.DPTpe) Type {
	rtpe := (*rtype)(u.Pointer(tpe))
	return rtpe
}
