package com.wang.oauth2.server.controller;

import com.wang.commons.model.domain.ResultInfo;
import com.wang.commons.model.domain.SignInIdentity;
import com.wang.commons.model.vo.SignInDinerInfo;
import com.wang.commons.utils.ResultInfoUtil;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * 用户中心
 */
@RestController
public class UserController {

    @Resource
    private HttpServletRequest request;

    @Resource
    private RedisTokenStore redisTokenStore;

    /**
     * 获取当前用户
     *
     * @param authentication
     * @return
     */
    @GetMapping("user/me")
    public ResultInfo getCurrentUser(Authentication authentication) {
        SignInIdentity identity = (SignInIdentity) authentication.getPrincipal();
        // 转为前台可用的 vo 对象
        SignInDinerInfo dinerInfo = new SignInDinerInfo();
        BeanUtils.copyProperties(identity, dinerInfo);
        return ResultInfoUtil.buildSuccess(request.getServletPath(), dinerInfo);
    }

    /**
     * 退出
     *
     * @param access_token
     * @param authorization
     * @return
     */
    @GetMapping("user/logout")
    public ResultInfo<String> logout(String access_token,
                                     @RequestHeader(value = "Authentication", required = false) String authorization) {
        // 判断 access_token 是否为空，为空将 authorization 赋值给 access_token
        if (StringUtils.isBlank(access_token)) {
            access_token = authorization;
        }
        // 判断 authorization 是否为空
        if (StringUtils.isBlank(access_token)) {
            return ResultInfoUtil.buildSuccess(request.getServletPath(), "退出成功");
        }
        // 判断 bearer token 是否为空
        if (access_token.toLowerCase().contains("bearer ".toLowerCase())) {
            access_token = access_token.toLowerCase().replace("bearer ", "");
        }
        // 清除 Redis Token 信息
        OAuth2AccessToken oAuth2AccessToken = redisTokenStore.readAccessToken(access_token);
        if (oAuth2AccessToken != null) {
            redisTokenStore.removeAccessToken(oAuth2AccessToken);
            OAuth2RefreshToken oAuth2RefreshToken = oAuth2AccessToken.getRefreshToken();
            redisTokenStore.removeRefreshToken(oAuth2RefreshToken);
            redisTokenStore.removeAccessTokenUsingRefreshToken(oAuth2RefreshToken);
        }
        return ResultInfoUtil.buildSuccess(request.getServletPath(), "退出成功");
    }
}
