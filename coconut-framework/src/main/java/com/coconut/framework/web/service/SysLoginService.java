package com.coconut.framework.web.service;

import javax.annotation.Resource;

import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthGiteeRequest;
import me.zhyd.oauth.request.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.coconut.common.constant.CacheConstants;
import com.coconut.common.constant.Constants;
import com.coconut.common.constant.UserConstants;
import com.coconut.common.core.domain.entity.SysUser;
import com.coconut.common.core.domain.model.LoginUser;
import com.coconut.common.core.redis.RedisCache;
import com.coconut.common.exception.ServiceException;
import com.coconut.common.exception.user.BlackListException;
import com.coconut.common.exception.user.CaptchaException;
import com.coconut.common.exception.user.CaptchaExpireException;
import com.coconut.common.exception.user.UserNotExistsException;
import com.coconut.common.exception.user.UserPasswordNotMatchException;
import com.coconut.common.utils.DateUtils;
import com.coconut.common.utils.MessageUtils;
import com.coconut.common.utils.StringUtils;
import com.coconut.common.utils.ip.IpUtils;
import com.coconut.framework.manager.AsyncManager;
import com.coconut.framework.manager.factory.AsyncFactory;
import com.coconut.framework.security.context.AuthenticationContextHolder;
import com.coconut.system.service.ISysConfigService;
import com.coconut.system.service.ISysUserService;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 登录校验方法
 *
 * @author ruoyi
 */
@Component
public class SysLoginService
{
    @Autowired
    private TokenService tokenService;

    @Resource
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private ISysUserService userService;

    @Autowired
    private ISysConfigService configService;

    /**
     * 登录验证
     *
     * @param username 用户名
     * @param password 密码
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public String login(String username, String password, String code, String uuid)
    {
        // 验证码校验
        validateCaptcha(username, code, uuid);
        // 登录前置校验
        loginPreCheck(username, password);
        // 用户验证
        Authentication authentication = null;
        try
        {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            AuthenticationContextHolder.setContext(authenticationToken);
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager.authenticate(authenticationToken);
        }
        catch (Exception e)
        {
            if (e instanceof BadCredentialsException)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
                throw new UserPasswordNotMatchException();
            }
            else
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, e.getMessage()));
                throw new ServiceException(e.getMessage());
            }
        }
        finally
        {
            AuthenticationContextHolder.clearContext();
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        recordLoginInfo(loginUser.getUserId());
        // 生成token
        return tokenService.createToken(loginUser);
    }

    /**
     * 校验验证码
     *
     * @param username 用户名
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public void validateCaptcha(String username, String code, String uuid)
    {
        boolean captchaEnabled = configService.selectCaptchaEnabled();
        if (captchaEnabled)
        {
            String verifyKey = CacheConstants.CAPTCHA_CODE_KEY + StringUtils.nvl(uuid, "");
            String captcha = redisCache.getCacheObject(verifyKey);
            redisCache.deleteObject(verifyKey);
            if (captcha == null)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.expire")));
                throw new CaptchaExpireException();
            }
            if (!code.equalsIgnoreCase(captcha))
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.error")));
                throw new CaptchaException();
            }
        }
    }

    /**
     * 登录前置校验
     * @param username 用户名
     * @param password 用户密码
     */
    public void loginPreCheck(String username, String password)
    {
        // 用户名或密码为空 错误
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("not.null")));
            throw new UserNotExistsException();
        }
        // 密码如果不在指定范围内 错误
        if (password.length() < UserConstants.PASSWORD_MIN_LENGTH
                || password.length() > UserConstants.PASSWORD_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // 用户名不在指定范围内 错误
        if (username.length() < UserConstants.USERNAME_MIN_LENGTH
                || username.length() > UserConstants.USERNAME_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // IP黑名单校验
        String blackStr = configService.selectConfigByKey("sys.login.blackIPList");
        if (IpUtils.isMatchedIp(blackStr, IpUtils.getIpAddr()))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("login.blocked")));
            throw new BlackListException();
        }
    }

    /**
     * 记录登录信息
     *
     * @param userId 用户ID
     */
    public void recordLoginInfo(Long userId)
    {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(userId);
        sysUser.setLoginIp(IpUtils.getIpAddr());
        sysUser.setLoginDate(DateUtils.getNowDate());
        userService.updateUserProfile(sysUser);
    }

    public String loginByOtherSource(String code, String source, String uuid) {

        // 先到数据库查询这个人曾经有没有登录过，没有就注册
        // 创建授权request
        AuthRequest authRequest = new AuthGiteeRequest(AuthConfig.builder()
                .clientId("6ec244b4618ea9c6b412255e4aedf15fc26f1277b3ab54c5166e627baf03bdbd")
                .clientSecret("325af1f9891d1fec8091c117d9ed6775545be75a648577ea5bf248e5b278b943")
                .redirectUri("http://localhost:1024/callback")
                .build());
        AuthResponse<AuthUser> login = authRequest.login(AuthCallback.builder().state(uuid).code(code).build());
        System.out.println(login);

        // 先查询数据库有没有该用户
        AuthUser authUser = login.getData();
        SysUser sysUser = new SysUser();
        sysUser.setUserName(authUser.getUsername());
        sysUser.setSource(authUser.getSource());
        List<SysUser> sysUsers = userService.selectUserListNoDataScope(sysUser);
        if (sysUsers.size() > 1) {
            throw new ServiceException("第三方登录异常，账号重叠");
        } else if (sysUsers.size() == 0) {
            // 相当于注册
            sysUser.setNickName(authUser.getNickname());
            sysUser.setAvatar(authUser.getAvatar());
            sysUser.setEmail(authUser.getEmail());
            sysUser.setRemark(authUser.getRemark());
            Long num = userService.registerUserAndGetUserId(sysUser);
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(sysUser.getUserName(), Constants.REGISTER,
                    MessageUtils.message("user.register.success")));
        } else {
            sysUser = sysUsers.get(0);
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(sysUser.getUserName(), Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        // 注册成功或者是已经存在的用户
        Set<String> permission = new HashSet<>();
        permission.add("Xxxix");  // 【自定义一个普通权限】
        LoginUser loginUser = new LoginUser(sysUser, permission);
        recordLoginInfo(loginUser.getUserId());
        // 生成token
        return tokenService.createToken(loginUser);
    }
}
