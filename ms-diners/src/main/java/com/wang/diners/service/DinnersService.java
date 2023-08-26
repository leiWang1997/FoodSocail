package com.wang.diners.service;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.wang.commons.constant.ApiConstant;
import com.wang.commons.model.domain.ResultInfo;
import com.wang.commons.model.dto.DinersDTO;
import com.wang.commons.model.pojo.Diners;
import com.wang.commons.utils.AssertUtil;
import com.wang.commons.utils.ResultInfoUtil;
import com.wang.diners.Mapper.DinersMapper;
import com.wang.diners.config.OAuth2ClientConfiguration;
import com.wang.diners.domain.OAuthDinerInfo;
import com.wang.diners.vo.LoginDinerInfo;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.util.LinkedHashMap;

/**
 * 食客业务层逻辑
 */
@Service
public class DinnersService {
    @Resource
    private RestTemplate restTemplate;
    @Value("${service.name.ms-oauth-server}")
    private String oauthServerName;
    @Resource
    private OAuth2ClientConfiguration oauth2ClientConfiguration;
    @Autowired
    private DinersMapper dinersMapper;
    @Autowired
    private SendVerifyCodeService sendVerifyCodeService;

    /**
     * 校验手机号是否已注册
     */
    public void checkPhoneIsRegistered(String phone) {
        AssertUtil.isNotEmpty(phone, "手机号不能为空");
        Diners diners = dinersMapper.selectByPhone(phone);
        AssertUtil.isTrue(diners == null, "该手机号未注册");
        AssertUtil.isTrue(diners.getIsValid() == 0, "该用户已锁定，请先解锁");
    }

    /**
     * 用户注册
     * @param dinersDTO
     * @param path
     * @return
     */
    public ResultInfo register (DinersDTO dinersDTO, String path){
        // 参数校验非空
        String username = dinersDTO.getUsername();
        AssertUtil.isNotEmpty(username, "请输入用户名");
        String password = dinersDTO.getPassword();
        AssertUtil.isNotEmpty(password, "请输入密码");
        String phone = dinersDTO.getPhone();
        AssertUtil.isNotEmpty(phone, "请输入手机号");
        String verifyCode = dinersDTO.getVerifyCode();
        AssertUtil.isNotEmpty(verifyCode, "请输入验证码");
        // 校验验证码一致性
        String code = sendVerifyCodeService.getCodeByPhone(phone);
        if(StringUtils.isBlank(code)){
            AssertUtil.isNotEmpty(code, "验证码已过期，请重新发送");
        }
        AssertUtil.isTrue(!dinersDTO.getVerifyCode().equals(code), "验证码不一致，请重新输入");
        // 验证用户名是否已注册
        Diners diners = dinersMapper.selectByUsername(username.trim());
        AssertUtil.isTrue(diners != null, "用户名已存在，请重新输入");
        // 注册
        // 密码加密
        dinersDTO.setPassword(DigestUtil.md5Hex(password.trim()));
        dinersMapper.save(dinersDTO);
        // 自动登录
        return signIn(username.trim(), password.trim(), path);
    }

    /**
     * 登录
     *
     * @param account  账号信息：用户名或手机或邮箱
     * @param password 密码
     * @param path     请求路径
     */
    public ResultInfo signIn(String account, String password, String path) {
        // 参数校验
        AssertUtil.isNotNull(account, "请输入登录账户");
        AssertUtil.isNotEmpty(password, "请输入登录密码");
        // 构建请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // 构建请求体（请求参数）
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("username", account);
        body.add("password", password);
        body.setAll(BeanUtil.beanToMap(oauth2ClientConfiguration));
        // 设置Authorization
        HttpEntity<MultiValueMap<String, Object>> entity = new HttpEntity<>(body, headers);
        // 设置Authorization
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(oauth2ClientConfiguration.getClientId(),
                oauth2ClientConfiguration.getSecret()));
        // 发送请求
        ResponseEntity<ResultInfo> result = restTemplate.postForEntity(oauthServerName + "oauth/token",
                entity, ResultInfo.class);
        AssertUtil.isTrue(result.getStatusCode() != HttpStatus.OK, "登录失败！");
        ResultInfo resultInfo = result.getBody();
        if (resultInfo.getCode() != ApiConstant.SUCCESS_CODE) {
            // 登录失败
            resultInfo.setData(resultInfo.getMessage());
            return resultInfo;
        }

        // 这里的data是一个LinkedHashMap，转成OAuthDinerInfo
        OAuthDinerInfo dinerInfo = BeanUtil.fillBeanWithMap((LinkedHashMap) resultInfo.getData(),
                new OAuthDinerInfo(), false);
        if (resultInfo.getCode() != ApiConstant.SUCCESS_CODE) {
            return resultInfo;
        }
        LoginDinerInfo loginDinerInfo = new LoginDinerInfo();
        loginDinerInfo.setToken(dinerInfo.getAccessToken());
        loginDinerInfo.setNickname(dinerInfo.getNickname());
        loginDinerInfo.setAvatarUrl(dinerInfo.getAvatarUrl());
        return ResultInfoUtil.buildSuccess(path, loginDinerInfo);
    }
}
