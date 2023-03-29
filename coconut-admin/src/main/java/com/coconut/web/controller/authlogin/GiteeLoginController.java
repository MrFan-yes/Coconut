package com.coconut.web.controller.authlogin;

import com.coconut.common.constant.Constants;
import com.coconut.common.core.domain.AjaxResult;
import com.coconut.common.utils.uuid.IdUtils;
import com.coconut.framework.web.service.SysLoginService;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.request.AuthGiteeRequest;
import me.zhyd.oauth.request.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GiteeLoginController {

    // 生成授权页面
    @GetMapping("/PreLoginByGitee")
    public AjaxResult PreLoginByGitee() {
        AjaxResult ajax = AjaxResult.success();
        // 创建授权request
        AuthRequest authRequest = new AuthGiteeRequest(AuthConfig.builder()
                .clientId("6ec244b4618ea9c6b412255e4aedf15fc26f1277b3ab54c5166e627baf03bdbd")
                .clientSecret("325af1f9891d1fec8091c117d9ed6775545be75a648577ea5bf248e5b278b943")
                .redirectUri("http://localhost:1024/callback")
                .build());
        String uuid = IdUtils.fastUUID();
        // 生成授权页面
        String authorizeUrl = authRequest.authorize(uuid);
        // 存储
        ajax.put("authorizeUrl", authorizeUrl);
        ajax.put("uuid", uuid);
        return ajax;
    }

    @Autowired
    private SysLoginService loginService;

    // 真正的第三方登录，回调地址映射过来的
    @PostMapping("/loginByGitee")
    public AjaxResult loginByGitee(@RequestBody LoginByOtherSourceBody loginByOtherSourceBody) {
        AjaxResult ajax = AjaxResult.success();
        String token = loginService
                .loginByOtherSource(loginByOtherSourceBody.getCode(), loginByOtherSourceBody.getSource(), loginByOtherSourceBody.getUuid());
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }
}
