package com.upgrad.FoodOrderingApp.service.entity;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.Entity;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "address")
@NamedQueries(
        {
                @NamedQuery(name = "addressByUuid", query = "select a from AddressEntity a where a.uuid = :uuid"),
                @NamedQuery(name = "getAllAddresses", query = "SELECT a FROM AddressEntity a WHERE a.id in :addressIds AND a.active = 1 order by a.id desc"),
                @NamedQuery(name = "addressById", query = "select a from AddressEntity a where a.id = :id"),

        }
)
public class AddressEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long  id;

    @Column(name = "UUID")
    @NotNull
    @Size(max = 200)
    private String uuid;

    @Column(name = "FLAT_BUIL_NUMBER")
    @Size(max = 255)
    private String flatBuildingNumber;

    @Column(name = "LOCALITY")
    @Size(max = 255)
    private String locality;

    @Column(name = "CITY")
    @Size(max = 30)
    private String city;

    @Column(name = "PINCODE")
    @NotNull
    @Size(max = 30)
    private String pincode;

    @ManyToOne(fetch = FetchType.EAGER)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "STATE_ID")
    private StateEntity state;

    @Column(name = "ACTIVE")
    private long active;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getFlatBuildingNumber() {
        return flatBuildingNumber;
    }

    public void setFlatBuildingNumber(String flatBuildingNumber) {
        this.flatBuildingNumber = flatBuildingNumber;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getPincode() {
        return pincode;
    }

    public void setPincode(String pincode) {
        this.pincode = pincode;
    }

    public StateEntity getState() {
        return state;
    }

    public void setState(StateEntity state) {
        this.state = state;
    }

    public long getActive() {
        return active;
    }

    public void setActive(long active) {
        this.active = active;
    }

}
