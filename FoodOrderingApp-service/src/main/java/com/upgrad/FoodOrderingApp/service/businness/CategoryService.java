package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CategoryDao;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CategoryService {

    @Autowired
    private CategoryDao categoryDao;

    public CategoryEntity getCategoryEntityById(final Integer categoryId){
        return  categoryDao.getCategoryById(categoryId);
    }

    public CategoryEntity getCategoryEntityByUuid(final String categoryUUId){
        return  categoryDao.getCategoryByUUId(categoryUUId);
    }

    public List<CategoryEntity> getAllCategories(){
        return  categoryDao.getAllCategories();
    }
}
