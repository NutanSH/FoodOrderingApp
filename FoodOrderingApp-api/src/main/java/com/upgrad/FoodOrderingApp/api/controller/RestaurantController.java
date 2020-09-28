package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.AddressService;
import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.businness.RestaurantService;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.InvalidRatingException;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;


@CrossOrigin
@RestController
@RequestMapping("/")
public class RestaurantController {

    @Autowired
    private RestaurantService restaurantService;

    @Autowired
    private AddressService addressService;

    @Autowired
    private CategoryService categoryService;

    @RequestMapping(method = RequestMethod.GET, path = "/restaurant", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> getAllRestaurants(){

        final List<RestaurantEntity> allRestaurants = restaurantService.getAllRestaurants();

        RestaurantListResponse restaurantListResponse = new RestaurantListResponse();

        for(RestaurantEntity restaurant : allRestaurants){
            RestaurantList info = new RestaurantList();
            info.setId(UUID.fromString(restaurant.getUuid()));
            info.setRestaurantName(restaurant.getRestaurantName());
            info.setPhotoURL(restaurant.getPhotoUrl());
            info.setCustomerRating(BigDecimal.valueOf(restaurant.getCustomerRating()));
            info.setAveragePrice(restaurant.getAvgPriceForTwo());
            info.setNumberCustomersRated(restaurant.getNumCustomersRated());

            AddressEntity addressEntity = addressService.getAddressById(restaurant.getAddress().getId());
            RestaurantDetailsResponseAddress responseAddress = new RestaurantDetailsResponseAddress()
                    .id(UUID.fromString(addressEntity.getUuid()))
                    .flatBuildingName(addressEntity.getFlatBuildingNumber())
                    .locality(addressEntity.getLocality())
                    .city(addressEntity.getCity())
                    .pincode(addressEntity.getPincode());

            final StateEntity stateEntity = addressService.getStateById(addressEntity.getState().getId());
            RestaurantDetailsResponseAddressState responseAddressState = new RestaurantDetailsResponseAddressState()
                    .id(UUID.fromString(stateEntity.getUuid()))
                    .stateName(stateEntity.getStateName());

            responseAddress.setState(responseAddressState);
            info.setAddress(responseAddress);

            List<String> categoryLists = new ArrayList();
            for (CategoryEntity categoryEntity :restaurant.getCategoryEntities()) {
                categoryLists.add(categoryEntity.getCategoryName());
            }

            Collections.sort(categoryLists);

            info.setCategories(String.join(",", categoryLists));
            restaurantListResponse.addRestaurantsItem(info);
        }
        return new ResponseEntity<RestaurantListResponse>(restaurantListResponse, HttpStatus.OK);
    }


    @RequestMapping(method = RequestMethod.GET, path = "/restaurant/name/{restaurant_name}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> getRestaurantsByName(@PathVariable String restaurant_name) throws RestaurantNotFoundException {

        final List<RestaurantEntity> allRestaurants = restaurantService.getRestaurantsByName(restaurant_name);
        RestaurantListResponse restaurantListResponse = new RestaurantListResponse();

        for (RestaurantEntity restaurant : allRestaurants) {
            RestaurantList info = new RestaurantList();
            info.setId(UUID.fromString(restaurant.getUuid()));
            info.setRestaurantName(restaurant.getRestaurantName());
            info.setPhotoURL(restaurant.getPhotoUrl());
            info.setCustomerRating(BigDecimal.valueOf(restaurant.getCustomerRating()));
            info.setAveragePrice(restaurant.getAvgPriceForTwo());
            info.setNumberCustomersRated(restaurant.getNumCustomersRated());

            AddressEntity addressEntity = addressService.getAddressById(restaurant.getAddress().getId());
            RestaurantDetailsResponseAddress responseAddress = new RestaurantDetailsResponseAddress()
                    .id(UUID.fromString(addressEntity.getUuid()))
                    .flatBuildingName(addressEntity.getFlatBuildingNumber())
                    .locality(addressEntity.getLocality())
                    .city(addressEntity.getCity())
                    .pincode(addressEntity.getPincode());

            final StateEntity stateEntity = addressService.getStateById(addressEntity.getState().getId());
            RestaurantDetailsResponseAddressState responseAddressState = new RestaurantDetailsResponseAddressState()
                    .id(UUID.fromString(stateEntity.getUuid()))
                    .stateName(stateEntity.getStateName());

            responseAddress.setState(responseAddressState);
            info.setAddress(responseAddress);

            List<String> categoryLists = new ArrayList();
            for (CategoryEntity categoryEntity : restaurant.getCategoryEntities()) {
                categoryLists.add(categoryEntity.getCategoryName());
            }

            Collections.sort(categoryLists);

            info.setCategories(String.join(",", categoryLists));
            restaurantListResponse.addRestaurantsItem(info);
        }
        return new ResponseEntity<RestaurantListResponse>(restaurantListResponse, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.GET, path = "/restaurant/category/{category_id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> getRestaurantByCategoryId(@PathVariable String category_id) throws CategoryNotFoundException {

        if(category_id == null){
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }

        final CategoryEntity categoryEntity = categoryService.getCategoryEntityByUuid(category_id);

        if(categoryEntity == null){
            throw new CategoryNotFoundException("CNF-002", "No category by this id");
        }

        final List<RestaurantCategoryEntity> allRestaurantCategories = restaurantService.getRestaurantByCategoryId(categoryEntity.getId());

        RestaurantListResponse restaurantListResponse = new RestaurantListResponse();

        for (RestaurantCategoryEntity restaurantCategoryEntity:allRestaurantCategories) {
            RestaurantEntity restaurant = restaurantCategoryEntity.getRestaurant();
            RestaurantList info = new RestaurantList();
            info.setId(UUID.fromString(restaurant.getUuid()));
            info.setRestaurantName(restaurant.getRestaurantName());
            info.setPhotoURL(restaurant.getPhotoUrl());
            info.setCustomerRating(BigDecimal.valueOf(restaurant.getCustomerRating()));
            info.setAveragePrice(restaurant.getAvgPriceForTwo());
            info.setNumberCustomersRated(restaurant.getNumCustomersRated());

            AddressEntity addressEntity = addressService.getAddressById(restaurant.getAddress().getId());
            RestaurantDetailsResponseAddress responseAddress = new RestaurantDetailsResponseAddress()
                    .id(UUID.fromString(addressEntity.getUuid()))
                    .flatBuildingName(addressEntity.getFlatBuildingNumber())
                    .locality(addressEntity.getLocality())
                    .city(addressEntity.getCity())
                    .pincode(addressEntity.getPincode());

            final StateEntity stateEntity = addressService.getStateById(addressEntity.getState().getId());
            RestaurantDetailsResponseAddressState responseAddressState = new RestaurantDetailsResponseAddressState()
                    .id(UUID.fromString(stateEntity.getUuid()))
                    .stateName(stateEntity.getStateName());

            responseAddress.setState(responseAddressState);
            info.setAddress(responseAddress);

            List<String> categoryLists = new ArrayList<String>();
            for (CategoryEntity category :restaurant.getCategoryEntities()) {
                categoryLists.add(category.getCategoryName());
            }

            Collections.sort(categoryLists);
            info.setCategories(String.join(",", categoryLists));

            restaurantListResponse.addRestaurantsItem(info);
        }

        return new ResponseEntity<RestaurantListResponse>(restaurantListResponse, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.GET, path = "/restaurant/{restaurant_id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantDetailsResponse> getRestaurantByUUId(@PathVariable String restaurant_id) throws RestaurantNotFoundException {

        if(restaurant_id == null){
            throw new RestaurantNotFoundException("RNF-002", "Restaurant id field should not be empty");
        }

        final RestaurantEntity restaurant = restaurantService.getRestaurantByUUId(restaurant_id);

        if(restaurant == null){
            throw new RestaurantNotFoundException("RNF-001", "No restaurant by this id");
        }

        RestaurantDetailsResponse detailsResponse = new RestaurantDetailsResponse();
        detailsResponse.setId(UUID.fromString(restaurant.getUuid()));
        detailsResponse.setRestaurantName(restaurant.getRestaurantName());
        detailsResponse.setPhotoURL(restaurant.getPhotoUrl());
        detailsResponse.setCustomerRating(BigDecimal.valueOf(restaurant.getCustomerRating()));
        detailsResponse.setAveragePrice(restaurant.getAvgPriceForTwo());
        detailsResponse.setNumberCustomersRated(restaurant.getNumCustomersRated());

        AddressEntity addressEntity = addressService.getAddressById(restaurant.getAddress().getId());
        RestaurantDetailsResponseAddress responseAddress = new RestaurantDetailsResponseAddress()
                .id(UUID.fromString(addressEntity.getUuid()))
                .flatBuildingName(addressEntity.getFlatBuildingNumber())
                .locality(addressEntity.getLocality())
                .city(addressEntity.getCity())
                .pincode(addressEntity.getPincode());

        final StateEntity stateEntity = addressService.getStateById(addressEntity.getState().getId());
        RestaurantDetailsResponseAddressState responseAddressState = new RestaurantDetailsResponseAddressState()
                .id(UUID.fromString(stateEntity.getUuid()))
                .stateName(stateEntity.getStateName());

        responseAddress.setState(responseAddressState);
        detailsResponse.setAddress(responseAddress);


        List<CategoryList> categoryLists = new ArrayList();
        for (CategoryEntity categoryEntity :restaurant.getCategoryEntities()) {
            CategoryList categoryListDetail = new CategoryList();
            categoryListDetail.setId(UUID.fromString(categoryEntity.getUuid()));
            categoryListDetail.setCategoryName(categoryEntity.getCategoryName());

            List<ItemList> itemLists = new ArrayList();
            for (ItemEntity itemEntity :categoryEntity.getItemEntities()) {
                ItemList itemDetail = new ItemList();
                itemDetail.setId(UUID.fromString(itemEntity.getUuid()));
                itemDetail.setItemName(itemEntity.getItemName());
                itemDetail.setPrice(itemEntity.getPrice());
                itemDetail.setItemType(ItemList.ItemTypeEnum.valueOf(itemEntity.getType().getValue()));
                itemLists.add(itemDetail);
            }
            categoryListDetail.setItemList(itemLists);
            categoryLists.add(categoryListDetail);
        }

        detailsResponse.setCategories(categoryLists);

        return new ResponseEntity<RestaurantDetailsResponse>(detailsResponse, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.PUT, path = "/restaurant/{restaurant_id}",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantUpdatedResponse> updateCustomerRating(@RequestHeader("authorization") final String authorization, @RequestParam Double customerRating, @PathVariable String restaurant_id )
            throws AuthorizationFailedException, InvalidRatingException, RestaurantNotFoundException {

        String[] bearerToken = authorization.split("Bearer ");
        RestaurantEntity restaurantEntity = restaurantService.updateRestaurant(customerRating, restaurant_id, bearerToken[1]);

        return new ResponseEntity<RestaurantUpdatedResponse>
                (new RestaurantUpdatedResponse().id(UUID.fromString(restaurantEntity.getUuid())).status("RESTAURANT RATING UPDATED SUCCESSFULLY"), HttpStatus.OK);
    }
}
