package router

import (
	"github.com/gin-gonic/gin"
	"metaflow/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())
}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		// TODO: ip从配置文件里取
		args["ip"] = c.Query("ip")
		args["db"] = c.PostForm("db")
		args["sql"] = c.PostForm("sql")
		data, err := service.Execute(args)
		JsonResponse(c, data, err)
	})
}
