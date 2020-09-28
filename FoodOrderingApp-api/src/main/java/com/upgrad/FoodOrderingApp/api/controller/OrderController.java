package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.*;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.time.ZonedDateTime;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;


@CrossOrigin
@RestController
@RequestMapping("/order")
public class OrderController {


    @Autowired
    private OrderService orderService;

    @Autowired
    private CouponService couponService;

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private AddressService addressService;

    @Autowired
    private StateService stateService;

    @Autowired
    private RestaurantService restaurantService;

    @Autowired
    private ItemService itemService;

    @RequestMapping(method = RequestMethod.GET,path = "/coupon/{coupon_name}",produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<CouponDetailsResponse> getCouponByCouponName(@RequestHeader(value = "authorization") final String authorization,
                                                                       @PathVariable(value = "coupon_name")final String couponName) throws AuthorizationFailedException, CouponNotFoundException {

        String[] bearerToken = authorization.split( "Bearer ");

        if(couponName == null){
            throw new CouponNotFoundException("CPF-002", "Coupon name field should not be empty");
        }

        CouponEntity couponEntity = orderService.getCouponByName(couponName, bearerToken[1]);

        if (couponEntity == null) {
            throw new CouponNotFoundException("CPF-001", "No coupon by this name");
        }
        CouponDetailsResponse couponDetailsResponse = new CouponDetailsResponse().id(UUID.fromString(couponEntity.getUuid()))
                .couponName(couponEntity.getCouponName()).percent(couponEntity.getPercent());

        return new ResponseEntity<CouponDetailsResponse>(couponDetailsResponse, HttpStatus.OK);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST,path = "",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SaveOrderResponse> saveOrder(@RequestHeader(value = "authorization")final String authorization, @RequestBody(required = false) final SaveOrderRequest saveOrderRequest) throws AuthorizationFailedException, PaymentMethodNotFoundException, AddressNotFoundException, RestaurantNotFoundException, CouponNotFoundException ,ItemNotFoundException{

        String accessToken = authorization.split("Bearer ")[1];
        final CustomerAuthTokenEntity customerAuthToken = customerService.getCustomerAuthToken(accessToken);
        CustomerEntity customerEntity = customerAuthToken.getCustomer();

        CouponEntity couponEntity = orderService.getCouponByCouponId(saveOrderRequest.getCouponId().toString());

        PaymentEntity paymentEntity = paymentService.getPaymentByUuid(saveOrderRequest.getPaymentId().toString());

        AddressEntity addressEntity = addressService.getAddressByUuid(saveOrderRequest.getAddressId());

        RestaurantEntity restaurantEntity = restaurantService.getRestaurantByUUId(saveOrderRequest.getRestaurantId().toString());

        final ZonedDateTime now = ZonedDateTime.now();
        OrdersEntity ordersEntity = new OrdersEntity();
        ordersEntity.setUuid(UUID.randomUUID().toString());
        ordersEntity.setBill(saveOrderRequest.getBill().floatValue());
        ordersEntity.setDate(now);
        ordersEntity.setCustomer(customerEntity);
        ordersEntity.setDiscount(saveOrderRequest.getDiscount().doubleValue());
        ordersEntity.setPayment(paymentEntity);
        ordersEntity.setAddress(addressEntity);
        ordersEntity.setRestaurant(restaurantEntity);
        ordersEntity.setCoupon(couponEntity);

        OrdersEntity savedOrderEntity = orderService.saveOrder(ordersEntity);

        List<ItemQuantity> itemQuantities = saveOrderRequest.getItemQuantities();
        for(ItemQuantity itemQuantity : itemQuantities) {

            OrderItemEntity orderItemEntity = new OrderItemEntity();

            ItemEntity itemEntity = itemService.getItemEntityByUuid(itemQuantity.getItemId().toString());

            orderItemEntity.setItem(itemEntity);
            orderItemEntity.setOrders(ordersEntity);
            orderItemEntity.setPrice(itemQuantity.getPrice());
            orderItemEntity.setQuantity(itemQuantity.getQuantity());

            OrderItemEntity savedOrderItem = orderService.saveOrderItem(orderItemEntity);
        }

        SaveOrderResponse saveOrderResponse = new SaveOrderResponse()
                .id(savedOrderEntity.getUuid())
                .status("ORDER SUCCESSFULLY PLACED");
        return new ResponseEntity<SaveOrderResponse>(saveOrderResponse,HttpStatus.CREATED);
    }


    @RequestMapping(method = RequestMethod.GET,path = "",produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<CustomerOrderResponse> getPastOrderOfUser(@RequestHeader(value = "authorization")final String authorization) throws AuthorizationFailedException {

        String accessToken = authorization.split("Bearer ")[1];
        final CustomerAuthTokenEntity customerAuthToken = customerService.getCustomerAuthToken(accessToken);
        CustomerEntity customerEntity = customerAuthToken.getCustomer();

        List<OrdersEntity> ordersEntities =  orderService.getOrdersByCustomers(customerEntity.getUuid());

        List<OrderList> orderLists = new LinkedList<>();

        if(ordersEntities != null){
            for(OrdersEntity ordersEntity:ordersEntities){
                List<OrderItemEntity> orderItemEntities = orderService.getOrderItemsByOrder(ordersEntity);

                List<ItemQuantityResponse> itemQuantityResponseList = new LinkedList<>();
                orderItemEntities.forEach(orderItemEntity -> {
                    ItemQuantityResponseItem itemQuantityResponseItem = new ItemQuantityResponseItem()
                            .itemName(orderItemEntity.getItem().getItemName())
                            .itemPrice(orderItemEntity.getItem().getPrice())
                            .id(UUID.fromString(orderItemEntity.getItem().getUuid()))
                            .type(ItemQuantityResponseItem.TypeEnum.valueOf(orderItemEntity.getItem().getType().getValue()));

                    ItemQuantityResponse itemQuantityResponse = new ItemQuantityResponse()
                            .item(itemQuantityResponseItem)
                            .quantity(orderItemEntity.getQuantity())
                            .price(orderItemEntity.getPrice());
                    itemQuantityResponseList.add(itemQuantityResponse);
                });

                OrderListAddressState orderListAddressState = new OrderListAddressState()
                        .id(UUID.fromString(ordersEntity.getAddress().getState().getUuid()))
                        .stateName(ordersEntity.getAddress().getState().getStateName());

                OrderListAddress orderListAddress = new OrderListAddress()
                        .id(UUID.fromString(ordersEntity.getAddress().getUuid()))
                        .flatBuildingName(ordersEntity.getAddress().getFlatBuildingNumber())
                        .locality(ordersEntity.getAddress().getLocality())
                        .city(ordersEntity.getAddress().getCity())
                        .pincode(ordersEntity.getAddress().getPincode())
                        .state(orderListAddressState);

                OrderListCoupon orderListCoupon = new OrderListCoupon()
                        .couponName(ordersEntity.getCoupon().getCouponName())
                        .id(UUID.fromString(ordersEntity.getCoupon().getUuid()))
                        .percent(ordersEntity.getCoupon().getPercent());


                OrderListCustomer orderListCustomer = new OrderListCustomer()
                        .id(UUID.fromString(ordersEntity.getCustomer().getUuid()))
                        .firstName(ordersEntity.getCustomer().getFirstName())
                        .lastName(ordersEntity.getCustomer().getLastName())
                        .emailAddress(ordersEntity.getCustomer().getEmail())
                        .contactNumber(ordersEntity.getCustomer().getContactNumber());


                OrderListPayment orderListPayment = new OrderListPayment()
                        .id(UUID.fromString(ordersEntity.getPayment().getUuid()))
                        .paymentName(ordersEntity.getPayment().getPaymentName());


                OrderList orderList = new OrderList()
                        .id(UUID.fromString(ordersEntity.getUuid()))
                        .itemQuantities(itemQuantityResponseList)
                        .address(orderListAddress)
                        .bill(BigDecimal.valueOf(ordersEntity.getBill()))
                        .date(String.valueOf(ordersEntity.getDate()))
                        .discount(BigDecimal.valueOf(ordersEntity.getDiscount()))
                        .coupon(orderListCoupon)
                        .customer(orderListCustomer)
                        .payment(orderListPayment);
                orderLists.add(orderList);
            }

            CustomerOrderResponse customerOrderResponse = new CustomerOrderResponse()
                    .orders(orderLists);
            return new ResponseEntity<CustomerOrderResponse>(customerOrderResponse,HttpStatus.OK);
        }else {
            return new ResponseEntity<CustomerOrderResponse>(new CustomerOrderResponse(),HttpStatus.OK);
        }


    }


}
