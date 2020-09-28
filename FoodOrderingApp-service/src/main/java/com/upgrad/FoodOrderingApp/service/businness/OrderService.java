package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CouponDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.dao.OrderDao;
import com.upgrad.FoodOrderingApp.service.dao.OrderItemDao;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.CouponNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.List;



@Service
public class OrderService {


    @Autowired
    OrderDao orderDao;

    @Autowired
    CouponDao couponDao;

    @Autowired
    OrderItemDao orderItemDao;

    @Autowired
    CustomerDao customerDao;

    @Autowired
    CustomerService customerService;



    public CouponEntity getCouponByCouponName(String couponName) throws CouponNotFoundException {
        if(couponName == null){
            throw new CouponNotFoundException("CPF-002","Coupon name field should not be empty");
        }

        CouponEntity couponEntity = couponDao.getCouponByCouponName(couponName);
        if(couponEntity == null){
            throw new CouponNotFoundException("CPF-001","No coupon by this name");
        }
        return couponEntity;
    }

    @Transactional
    public CouponEntity getCouponByName(String couponName, final String authorizationToken) throws AuthorizationFailedException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }
        return orderDao.getCouponByName(couponName);
    }


    public CouponEntity getCouponByCouponId(String couponUuid) throws CouponNotFoundException {

        CouponEntity couponEntity = couponDao.getCouponByUuid(couponUuid);
        if(couponEntity == null){
            throw new CouponNotFoundException("CPF-002","No coupon by this id");
        }
        return couponEntity;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public OrdersEntity saveOrder(OrdersEntity ordersEntity) {
        return orderDao.saveOrder(ordersEntity);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public OrderItemEntity saveOrderItem (OrderItemEntity orderItemEntity){

        OrderItemEntity savedOrderItemEntity = orderItemDao.createOrderItemEntity(orderItemEntity);
        return savedOrderItemEntity;
    }

    public List<OrdersEntity> getOrdersByCustomers(String customerUuid) {

        CustomerEntity customerEntity = customerDao.getCustomerByUuid(customerUuid);

        List<OrdersEntity> ordersEntities = orderDao.getCustomerOrders(customerEntity);
        return ordersEntities;
    }

    public List<OrderItemEntity> getOrderItemsByOrder(OrdersEntity ordersEntity) {
        List<OrderItemEntity> orderItemEntities = orderItemDao.getItemsByOrder(ordersEntity);
        return orderItemEntities;
    }
}

