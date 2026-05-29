package org.cdpg.dx.database.elastic.model;

import java.util.List;

/**
 * DTO for access policy filter parameters.
 */
public class AccessPolicyRequestDTO {

  private String sub;
  private Boolean myAssetsReq;
  private List<String> sharedItemIds;

  public AccessPolicyRequestDTO(String sub, Boolean myAssetsReq) {
    this.sub = sub;
    this.myAssetsReq = myAssetsReq;
  }

  public String getSub() {
    return sub;
  }

  public void setSub(String sub) {
    this.sub = sub;
  }

  public Boolean getMyAssetsReq() {
    return myAssetsReq;
  }

  public void setMyAssetsReq(Boolean myAssetsReq) {
    this.myAssetsReq = myAssetsReq;
  }

  public List<String> getSharedItemIds() {
    return sharedItemIds;
  }

  public void setSharedItemIds(List<String> sharedItemIds) {
    this.sharedItemIds = sharedItemIds;
  }
}
