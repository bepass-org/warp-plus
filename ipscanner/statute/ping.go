package statute

import (
	"context"
	"fmt"
)

type IPingResult interface {
	Result() IPInfo
	Error() error
	fmt.Stringer
}

type IPing interface {
	Ping() IPingResult
	PingContext(context.Context) IPingResult
}
