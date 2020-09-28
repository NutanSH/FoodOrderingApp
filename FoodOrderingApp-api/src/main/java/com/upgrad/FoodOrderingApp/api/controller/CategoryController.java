package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.CategoriesListResponse;
import com.upgrad.FoodOrderingApp.api.model.CategoryDetailsResponse;
import com.upgrad.FoodOrderingApp.api.model.CategoryListResponse;
import com.upgrad.FoodOrderingApp.api.model.ItemList;
import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.ItemEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@CrossOrigin
@RestController
@RequestMapping("/")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    @RequestMapping(method = RequestMethod.GET, path = "/category", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<CategoriesListResponse> getAllCategories() {

        final List<CategoryEntity> allCategories = categoryService.getAllCategories();

        CategoriesListResponse categoriesListResponse = new CategoriesListResponse();

        for (CategoryEntity category: allCategories) {
            CategoryListResponse categoryDetail = new CategoryListResponse();
            categoryDetail.setId(UUID.fromString(category.getUuid()));
            categoryDetail.setCategoryName(category.getCategoryName());
            categoriesListResponse.addCategoriesItem(categoryDetail);
        }

        return new ResponseEntity<CategoriesListResponse>(categoriesListResponse, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.GET, path = "/category/{category_id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<CategoryDetailsResponse> getCategoryById(@PathVariable String category_id) throws CategoryNotFoundException {

        if(category_id == null){
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }

        final CategoryEntity category = categoryService.getCategoryEntityByUuid(category_id);

        if(category == null){
            throw new CategoryNotFoundException("CNF-002", "No category by this id");
        }

        CategoryDetailsResponse categoryDetails = new CategoryDetailsResponse();
        categoryDetails.setId(UUID.fromString(category.getUuid()));
        categoryDetails.setCategoryName(category.getCategoryName());
        List<ItemList> itemLists = new ArrayList();
        for (ItemEntity itemEntity :category.getItemEntities()) {
            ItemList itemDetail = new ItemList();
            itemDetail.setId(UUID.fromString(itemEntity.getUuid()));
            itemDetail.setItemName(itemEntity.getItemName());
            itemDetail.setPrice(itemEntity.getPrice());
            itemDetail.setItemType(ItemList.ItemTypeEnum.valueOf(itemEntity.getType().getValue()));
            itemLists.add(itemDetail);
        }
        categoryDetails.setItemList(itemLists);

        return new ResponseEntity<>(categoryDetails, HttpStatus.OK);
    }
}
