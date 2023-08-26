package com.wang.diners.controlller;

import com.wang.commons.model.domain.ResultInfo;
import com.wang.commons.model.dto.DinersDTO;
import com.wang.commons.utils.ResultInfoUtil;
import com.wang.diners.service.DinnersService;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@Api(tags = "食客相关接口")
public class DinnersController {

    @Autowired
    private DinnersService dinnersService;

    @Autowired
    private HttpServletRequest httpServletRequest;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private DinnersService dinersService;

    /**
     * 校验手机号是否已注册
     *
     * @param phone
     * @return
     */
    @GetMapping("checkPhone")
    public ResultInfo checkPhone(String phone) {

        dinersService.checkPhoneIsRegistered(phone);
        return ResultInfoUtil.buildSuccess(request.getServletPath());
    }

    /**
     * 注册
     *
     * @param dinersDTO
     * @return
     */
    @PostMapping("register")
    public ResultInfo register(@RequestBody DinersDTO dinersDTO) {
        return dinersService.register(dinersDTO, request.getServletPath());
    }

    /**
     *  登录
     * @param account
     * @param password
     * @return
     */
    @RequestMapping("/signIn")
    public ResultInfo signIn(String account, String password){
        return dinnersService.signIn(account, password, httpServletRequest.getServletPath());
    }
}
